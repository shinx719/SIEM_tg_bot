"""ELK Security 8.11.1 -> Telegram: Windows login, USB, and Office-to-shell detection alerts.

Compatible with earlier /data/notifications.db (sent and alert_states tables).
No Kibana write permissions are used.
"""
import base64
import csv
import io
import uuid
from html import escape
import urllib.parse
import json
import os
import sqlite3
import time
import threading
import queue
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/")
ES_USER = os.environ["ES_USER"]
ES_PASSWORD = os.environ["ES_PASSWORD"]
TG_TOKEN = os.environ["TG_TOKEN"]
TG_CHAT_ID = os.environ["TG_CHAT_ID"]
INDEX = os.getenv("ALERT_INDEX", ".alerts-security.alerts-default")
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "15"))
SEARCH_DAYS = int(os.getenv("SEARCH_DAYS", "30"))
MAX_ALERTS = 1000
LOCAL_TZ = timezone(timedelta(hours=6))
DB_PATH = "/data/notifications.db"
# Required: Telegram numeric user ID. Chat ID alone is NOT an authorization check.
ALLOWED_USER_ID = int(os.environ["TG_ALLOWED_USER_ID"])
COMMAND_POLL_SECONDS = 3
MENU_LIMIT = 8
REPORT_LIMIT = 300
# Public browser-accessible Kibana URL, e.g. http://192.168.1.10:5601
KIBANA_URL = os.getenv("KIBANA_URL", "").strip().rstrip("/")

# Очередь экспорта: один выполняемый отчёт и один ожидающий.
REPORT_QUEUE = queue.Queue(maxsize=1)


# Allowlist is configured without modifying Python code. Unknown rule kinds are generic.
CONFIG_PATH = os.getenv("SOC_RULES_CONFIG", "/app/rules.json")

def load_rules():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        config = json.load(f)
    rules = config.get("rules", [])
    allowed = {}
    for item in rules:
        name = str(item.get("name", "")).strip()
        kind = str(item.get("kind", "generic"))
        if name and item.get("enabled", True) and name != "WHOAMI":
            allowed[name] = kind
    if not allowed:
        raise ValueError("В rules.json нет разрешённых правил")
    return allowed

RULES = load_rules()
PERIODS = {24: "24 часа", 168: "7 дней", 720: "30 дней"}

STATUS_NAMES = {
    "open": "🔴 Открыт",
    "acknowledged": "🔵 Принят в работу",
    "closed": "🟢 Закрыт",
}


def setup_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS sent (
        id TEXT PRIMARY KEY, sent_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS alert_states (
        id TEXT PRIMARY KEY, status TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS bot_state (
        key TEXT PRIMARY KEY, value TEXT NOT NULL
    )""")
    db.commit()
    return db


def field(data, key, default=None):
    """Read both dotted Elastic keys and nested ECS objects."""
    if key in data:
        return data[key]
    value = data
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def format_time(value):
    if not value:
        return "Не указано"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(LOCAL_TZ).strftime("%d.%m.%Y %H:%M:%S")
    except (TypeError, ValueError):
        return "Не указано"


def find_alerts():
    auth = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    since = (datetime.now(timezone.utc) - timedelta(days=SEARCH_DAYS)).isoformat()
    query = {
        "size": MAX_ALERTS,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": [
            {"terms": {"kibana.alert.rule.name": list(RULES)}},
            {"range": {"@timestamp": {"gte": since}}},
        ]}},
    }
    req = urllib.request.Request(
        f"{ES_URL}/{INDEX}/_search",
        data=json.dumps(query).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        result = json.load(response)
    hits = result["hits"]["hits"]
    if len(hits) >= MAX_ALERTS:
        print("ВНИМАНИЕ: лимит поиска 1000; некоторые алерты могут быть пропущены", flush=True)
    return hits


def send_telegram(message):
    payload = json.dumps({"chat_id": TG_CHAT_ID, "text": message}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
        data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        result = json.load(response)
    return result.get("ok", False)


def telegram_api(method, payload):
    """POST to Telegram without putting message data in URL."""
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TG_TOKEN}/{method}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            description = json.loads(body).get("description", "Unknown error")
        except ValueError:
            description = "Unable to parse Telegram error"
        raise RuntimeError(
            f"Telegram {method}: HTTP {exc.code}: {description}"
        ) from None
    if not result.get("ok"):
        raise RuntimeError(f"Telegram {method} did not return ok")
    return result.get("result")


def get_offset(db):
    row = db.execute("SELECT value FROM bot_state WHERE key='tg_offset'").fetchone()
    return int(row[0]) if row else 0


def set_offset(db, offset):
    with db:
        db.execute("INSERT INTO bot_state(key,value) VALUES ('tg_offset',?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(offset),))


def es_query(body):
    auth = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        f"{ES_URL}/{INDEX}/_search",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)



def es_query_index(index, body):
    """Чтение Elasticsearch из явно разрешённого индекса."""
    allowed_indices = {"winlogbeat-*"}
    if index not in allowed_indices:
        raise ValueError("Индекс не разрешён")

    auth = base64.b64encode(
        f"{ES_USER}:{ES_PASSWORD}".encode()
    ).decode()

    req = urllib.request.Request(
        f"{ES_URL}/{index}/_search",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}"
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)




def correlate_failed_logons(alert):
    """Сопоставляет Threshold-алерт с исходными событиями 4625."""
    threshold = field(alert, "kibana.alert.threshold_result", {}) or {}
    start = threshold.get("from")
    end = field(alert, "kibana.alert.original_time")
    host = get_host(alert)
    expected = threshold.get("count")

    if not start or not end or not host or host == "-":
        return {"verified": False, "reason": "Недостаточно данных"}

    filters = [
        {"term": {"event.code": "4625"}},
        {"term": {"host.name": host}},
        {"range": {"@timestamp": {"gte": start, "lte": end}}}
    ]

    fields = {
        "ip": "source.ip",
        "user": "user.name",
        "logon_type": "winlog.event_data.LogonType",
        "status": "winlog.event_data.Status",
        "substatus": "winlog.event_data.SubStatus"
    }

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            name: {"terms": {"field": elastic_field, "size": 20}}
            for name, elastic_field in fields.items()
        }
    }

    result = es_query_index("winlogbeat-*", body)
    actual = result["hits"]["total"]["value"]

    distributions = {
        name: {
            str(bucket["key"]): bucket["doc_count"]
            for bucket in result["aggregations"][name]["buckets"]
        }
        for name in fields
    }

    return {
        "verified": actual == expected,
        "expected": expected,
        "actual": actual,
        "host": host,
        "start": start,
        "end": end,
        "distributions": distributions
    }




def failed_logon_details(alert):
    """Дополнительная аналитика 4625 без остановки экспорта."""
    try:
        result = correlate_failed_logons(alert)
    except Exception as exc:
        print(
            f"Не удалось получить аналитику 4625: "
            f"{type(exc).__name__}",
            flush=True
        )
        return "Исходные события: данные временно недоступны"

    expected = result.get("expected")
    actual = result.get("actual")
    distributions = result.get("distributions", {})

    if expected is None or actual is None:
        return "Исходные события: недостаточно данных"

    parts = [
        f"Сопоставлено событий: {actual} из {expected}"
    ]

    if not result.get("verified"):
        parts.append(
            "Внимание: количество исходных событий не совпадает"
        )
        return "\n".join(parts)

    labels = {
        "ip": "IP",
        "user": "Пользователь",
        "logon_type": "Тип входа",
        "status": "Status",
        "substatus": "SubStatus"
    }

    for key, label in labels.items():
        values = distributions.get(key, {})
        if values:
            summary = ", ".join(
                f"{value} ({count})"
                for value, count in values.items()
            )
            parts.append(f"{label}: {summary}")

    parts.append(
        "Сопоставление по компьютеру и времени; "
        "состав исходных документов не подтверждён."
    )

    return "\n".join(parts)



def build_statistics(period_hours=None, rule_name=None):
    filters = [{"terms": {"kibana.alert.rule.name": list(RULES)}}]
    if rule_name:
        if rule_name not in RULES:
            raise ValueError("Недопустимое правило")
        filters.append({"term": {"kibana.alert.rule.name": rule_name}})
    if period_hours is not None:
        since = (datetime.now(timezone.utc) - timedelta(hours=period_hours)).isoformat()
        filters.append({"range": {"@timestamp": {"gte": since}}})
    named_filters = {name: {"term": {"kibana.alert.rule.name": name}} for name in RULES}
    body = {"size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "rules": {"filters": {"filters": named_filters}},
            "statuses": {"filters": {"filters": {
                "open": {"term": {"kibana.alert.workflow_status": "open"}},
                "acknowledged": {"term": {"kibana.alert.workflow_status": "acknowledged"}},
                "closed": {"term": {"kibana.alert.workflow_status": "closed"}}
            }}},
            "severities": {"filters": {"filters": {
                sev: {"term": {"kibana.alert.severity": sev}}
                for sev in ("low", "medium", "high", "critical")
            }}}
        }}
    result = es_query(body)
    return {"total": result["hits"]["total"]["value"],
        "rules": {k:v["doc_count"] for k,v in result["aggregations"]["rules"]["buckets"].items()},
        "statuses": {k:v["doc_count"] for k,v in result["aggregations"]["statuses"]["buckets"].items()},
        "severities": {k:v["doc_count"] for k,v in result["aggregations"]["severities"]["buckets"].items()}}

def stats_text(report=False):
    period = 24 if report else None
    data = build_statistics(period)
    title = "📅 ОТЧЁТ ЗА 24 ЧАСА" if report else "📊 СТАТИСТИКА SOC"
    scope = "За последние 24 часа (по времени создания)" if report else "Все сохранённые алерты разрешённых правил"
    lines = [title, scope, f"🕒 Сформирован: {format_time(datetime.now(timezone.utc).isoformat())} (UTC+6)", "",
             f"Всего: {data['total']}",
             f"🔴 Открыто: {data['statuses']['open']}",
             f"🔵 В работе: {data['statuses']['acknowledged']}",
             f"🟢 Закрыто: {data['statuses']['closed']}", "", "По правилам:"]
    for name, count in data["rules"].items():
        lines.append(f"• {name}: {count}")
    lines += ["", "По критичности:"]
    for key, label in (("critical", "Critical"), ("high", "High"),
                       ("medium", "Medium"), ("low", "Low")):
        lines.append(f"• {label}: {data['severities'][key]}")
    if report:
        lines += ["", "Статусы текущие, даже если изменены после создания алерта."]
    return "\n".join(lines)


def get_report_alerts(hours=24, rule_name=None):
    if rule_name is not None and rule_name not in RULES:
        raise ValueError("Недопустимое правило")
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    filters = [{"terms": {"kibana.alert.rule.name": list(RULES)}},
               {"range": {"@timestamp": {"gte": since}}}]
    if rule_name:
        filters.append({"term": {"kibana.alert.rule.name": rule_name}})
    body = {"size": REPORT_LIMIT, "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.workflow_status",
          "kibana.alert.severity", "host.name", "process.name", "process.parent.name",
          "winlog.event_data.DeviceDescription",
          "winlog.event_data.DeviceId",
          "kibana.alert.threshold_result",
          "kibana.alert.original_time",
          "event.code", "kibana.alert.reason",
          "process.command_line", "user.name", "source.ip"],
        "query": {"bool": {"filter": filters}}}
    result = es_query(body)
    rows = []
    for row_index, hit in enumerate(result["hits"]["hits"]):
        item = hit["_source"]
        rule = field(item, "kibana.alert.rule.name", "-")
        kind = RULES.get(rule, "generic")
        detail = "-"
        if kind == "login":
            threshold = field(item, "kibana.alert.threshold_result", {}) or {}
            parts = [f"Неудачных входов: {threshold.get('count', '?')}"]
            if threshold.get("from"):
                parts.append("Начало интервала: " + format_time(threshold["from"]))

            host = get_host(item)
            if row_index < 20 and host not in ("Не указан", "-", ""):
                extra = failed_logon_details(item)
                if extra:
                    parts.append(extra)

            detail = "\n".join(parts)

        elif kind == "usb":
            device = field(item, "winlog.event_data.DeviceDescription")
            device_id = field(item, "winlog.event_data.DeviceId")
            parts = [str(device or "USB-устройство")]
            if device_id:
                parts.append("Device ID: " + str(device_id))
            detail = "\n".join(parts)

        elif kind == "office_shell":
            parent = field(item, "process.parent.name") or "?"
            child = field(item, "process.name") or "?"
            command = field(item, "process.command_line")
            parts = [f"{parent} → {child}"]
            if command:
                parts.append("Команда: " + str(command)[:350])
            detail = "\n".join(parts)

        else:
            detail = str(
                field(item, "kibana.alert.reason")
                or field(item, "event.code")
                or "Событие обнаружения"
            )[:300]
        rows.append({"time": format_time(field(item,"@timestamp")),"rule":rule,
            "host":get_host(item), "severity":str(field(item,"kibana.alert.severity") or "-").upper(),
            "status":{"open":"Открыт","acknowledged":"В работе","closed":"Закрыт"}.get(field(item,"kibana.alert.workflow_status"),"Не указан"),
            "detail":detail})
    return rows, result["hits"]["total"]["value"]

def make_csv(rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";")
    writer.writerow(["Время (UTC+6)", "Правило", "Компьютер", "Критичность", "Статус", "Детали"])
    for row in rows:
        values = [str(row[k]) for k in ("time", "rule", "host", "severity", "status", "detail")]
        # Prevent spreadsheet formula injection in exported event strings.
        values = [("'" + value) if value.lstrip().startswith(("=", "+", "-", "@")) else value for value in values]
        writer.writerow(values)
    return ("\ufeff" + stream.getvalue()).encode("utf-8")


def make_pdf(stats, rows, total, hours=24, rule_name=None):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

    font_dir = "/usr/share/fonts/dejavu"
    if not os.path.exists(font_dir):
        font_dir = "/usr/share/fonts/dejavu"
    font_regular = font_dir + "/DejaVuSans.ttf"
    font_bold = font_dir + "/DejaVuSans-Bold.ttf"
    pdfmetrics.registerFont(TTFont("SOCDejaVu", font_regular))
    pdfmetrics.registerFont(TTFont("SOCDejaVuBold", font_bold))
    dark = colors.HexColor("#142338")
    blue = colors.HexColor("#1765B5")
    muted = colors.HexColor("#687788")
    light = colors.HexColor("#EFF5FB")
    regular = ParagraphStyle("NormalSOC", fontName="SOCDejaVu", fontSize=8.2, leading=13, textColor=dark)
    small = ParagraphStyle("SmallSOC", parent=regular, fontSize=7.3, leading=11)
    white = ParagraphStyle("WhiteSOC", parent=regular, textColor=colors.white, fontName="SOCDejaVuBold", fontSize=7.5)
    heading = ParagraphStyle("HeadingSOC", parent=regular, fontName="SOCDejaVuBold", fontSize=12, leading=17, spaceBefore=16, spaceAfter=8)
    title = ParagraphStyle("TitleSOC", parent=regular, fontName="SOCDejaVuBold", fontSize=19, leading=24)
    subtitle = ParagraphStyle("SubtitleSOC", parent=regular, fontSize=8, textColor=muted, spaceAfter=18)
    def par(value, style=small):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), style)
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, leftMargin=38, rightMargin=38,
                            topMargin=42, bottomMargin=46, title="ELK SOC - отчёт",
                            author="ELK SOC Assistant")
    width = A4[0] - 76
    story = [par("ELK SOC ASSISTANT", ParagraphStyle("EyebrowSOC", parent=regular, fontName="SOCDejaVuBold", textColor=blue, fontSize=9)),
             Spacer(1, 9), par("Отчёт по событиям безопасности", title),
             par("Период: " + PERIODS.get(hours, str(hours)+" ч") + " · Правило: " + (rule_name or "Все разрешённые") + " · UTC+6 · Сформирован: " + format_time(datetime.now(timezone.utc).isoformat()), subtitle)]
    cards = [[par("ВСЕГО АЛЕРТОВ", small), par("ОТКРЫТО", small), par("В РАБОТЕ", small), par("ЗАКРЫТО", small)],
             [par(stats["total"], heading), par(stats["statuses"]["open"], heading),
              par(stats["statuses"]["acknowledged"], heading), par(stats["statuses"]["closed"], heading)]]
    t = Table(cards, colWidths=[width / 4] * 4)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), light),
                          ("TOPPADDING", (0, 0), (-1, 0), 12), ("BOTTOMPADDING", (0, -1), (-1, -1), 12),
                          ("LEFTPADDING", (0, 0), (-1, -1), 12)]))
    story += [t, Spacer(1, 7), par("По правилам", heading)]
    visible_rules = (
        {rule_name: stats["rules"].get(rule_name, 0)}
        if rule_name
        else stats["rules"]
    )
    counts = [[par(k, regular), par(v, regular)] for k, v in visible_rules.items()]
    t = Table(counts, colWidths=[width - 70, 70])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), .4, colors.HexColor("#E0E8F0")),
                          ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 7),
                          ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    story.append(t)
    story.append(par("По критичности", heading))
    severities = [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]
    story.append(par("   ·   ".join(f"{label}: {stats['severities'][key]}" for label, key in severities), regular))
    story.append(par("Перечень инцидентов", heading))
    if total > len(rows):
        story.append(par(f"Показаны последние {len(rows)} из {total} алертов. Это не полный перечень.", regular))
        story.append(Spacer(1, 7))
    table_rows = [[par("Время", white), par("Правило / описание", white), par("ПК", white), par("Уровень", white), par("Статус", white)]]
    for row in rows:
        info = row["rule"] + "\n" + row["detail"]
        table_rows.append([par(row["time"]), par(info), par(row["host"]), par(row["severity"]), par(row["status"])])
    if not rows:
        table_rows.append([par("Нет событий за период"), "", "", "", ""])
    widths = [101, 182, 66, 66, width-415]
    t = Table(table_rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), dark),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8FC")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t)
    story += [Spacer(1, 12), par("Примечание: период определяется временем создания алерта. Статусы показаны на момент выгрузки. "
                                   "Отчёт включает только разрешённые правила из rules.json; WHOAMI исключено.", small)]
    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#DEE6EE"))
        canvas.line(38, 34, A4[0] - 38, 34)
        canvas.setFont("SOCDejaVu", 7)
        canvas.setFillColor(muted)
        canvas.drawString(38, 23, "ELK SOC Assistant  ·  Security monitoring")
        canvas.drawRightString(A4[0] - 38, 23, str(document.page))
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def send_file(filename, data, caption):
    boundary = "----ELKSOC" + uuid.uuid4().hex
    encoded = bytearray()
    def part(header, value):
        encoded.extend(("--" + boundary + "\r\n" + header + "\r\n\r\n").encode())
        encoded.extend(value)
        encoded.extend(b"\r\n")
    part('Content-Disposition: form-data; name="chat_id"', str(TG_CHAT_ID).encode())
    part('Content-Disposition: form-data; name="caption"', caption.encode("utf-8"))
    mime = "application/pdf" if filename.endswith(".pdf") else "text/csv"
    part(f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\nContent-Type: {mime}', data)
    encoded.extend(("--" + boundary + "--\r\n").encode())
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{TG_TOKEN}/sendDocument",
        data=bytes(encoded),
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        answer = json.load(response)
    if not answer.get("ok"):
        raise RuntimeError("Не удалось отправить документ Telegram")


def export_and_send(fmt, hours=24, rule_name=None):
    if fmt not in ("pdf", "csv") or hours not in PERIODS:
        raise ValueError("Неверный формат или период")
    if rule_name and rule_name not in RULES:
        raise ValueError("Правило не разрешено")
    stats = build_statistics(hours, rule_name)
    rows, total = get_report_alerts(hours, rule_name)
    now = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d_%H-%M")
    if fmt == "pdf":
        payload = make_pdf(stats, rows, total, hours, rule_name)
        name = f"ELK_SOC_Report_{hours}h_{now}.pdf"
    else:
        payload = make_csv(rows)
        name = f"ELK_SOC_Alerts_{hours}h_{now}.csv"
    label = rule_name or "все разрешённые правила"
    suffix = f"; показаны {len(rows)} из {total}" if total > len(rows) else f"; записей: {len(rows)}"
    send_file(name, payload, f"Отчёт: {PERIODS[hours]}, {label}" + suffix)


REPORT_LOCK = threading.Lock()
REPORT_PENDING = set()


def report_worker():
    """Последовательно выполняет отчёты в отдельном потоке."""
    while True:
        job = REPORT_QUEUE.get()
        try:
            fmt, hours, rule_name = job
            export_and_send(fmt, hours, rule_name)
            print(
                f"Отчёт отправлен: {fmt}, период {hours} ч.",
                flush=True
            )
        except Exception as exc:
            print(
                f"Ошибка фонового отчёта: "
                f"{type(exc).__name__}: {exc}",
                flush=True
            )
        finally:
            with REPORT_LOCK:
                REPORT_PENDING.discard(job)
            REPORT_QUEUE.task_done()


def queue_report(fmt, hours=24, rule_name=None):
    """Добавляет уникальное задание в очередь."""
    if fmt not in ("pdf", "csv") or hours not in PERIODS:
        raise ValueError("Недопустимый формат или период")

    if rule_name is not None and rule_name not in RULES:
        raise ValueError("Правило не разрешено")

    job = (fmt, hours, rule_name)

    with REPORT_LOCK:
        if job in REPORT_PENDING:
            return False

        try:
            REPORT_QUEUE.put_nowait(job)
        except queue.Full:
            return False

        REPORT_PENDING.add(job)
        return True



def request_report(fmt, hours=24, rule_name=None):
    """Ставит экспорт в очередь и сообщает пользователю результат."""
    accepted = queue_report(fmt, hours, rule_name)

    if accepted:
        message = (
            "⏳ Отчёт поставлен в очередь. "
            "Готовый файл придёт отдельным сообщением."
        )
    else:
        message = (
            "⚠️ Очередь отчётов занята. "
            "Повтори запрос после завершения текущего экспорта."
        )

    try:
        telegram_api("sendMessage", {
            "chat_id": TG_CHAT_ID,
            "text": message
        })
    except Exception as exc:
        print(
            f"Не удалось отправить подтверждение экспорта: "
            f"{type(exc).__name__}: {exc}",
            flush=True
        )

    return accepted



def menu_markup():
    return {"inline_keyboard": [
        [{"text": "📊 Статистика", "callback_data":"soc:stats"},
         {"text":"📋 Отчёт за 24 часа", "callback_data":"soc:report"}],
        [{"text":"🚨 Активные алерты", "callback_data":"soc:alerts"}],
        [{"text":"📄 Общий PDF / CSV", "callback_data":"sel:all"}],
        [{"text":"📋 PDF по правилу", "callback_data":"sel:rules"}],
        [{"text":"❓ Помощь", "callback_data":"soc:help"}]]}

def report_period_markup(rule_index):
    previous = "sel:rules" if rule_index >= 0 else "soc:menu"
    return {"inline_keyboard": [
        [{"text": "24 часа", "callback_data": f"period:{rule_index}:24"},
         {"text": "7 дней", "callback_data": f"period:{rule_index}:168"},
         {"text": "30 дней", "callback_data": f"period:{rule_index}:720"}],
        [{"text": "⬅️ Назад", "callback_data": previous},
         {"text": "🏠 Главное меню", "callback_data": "soc:menu"}]
    ]}


def report_format_markup(rule_index, hours):
    return {"inline_keyboard": [
        [{"text": "📄 PDF", "callback_data": f"export:pdf:{rule_index}:{hours}"},
         {"text": "📥 CSV", "callback_data": f"export:csv:{rule_index}:{hours}"}],
        [{"text": "⬅️ Назад", "callback_data": f"back:period:{rule_index}"},
         {"text": "🏠 Главное меню", "callback_data": "soc:menu"}]
    ]}


def rule_choice_markup():
    buttons = [
        [{"text": name[:55], "callback_data": f"choose:{i}"}]
        for i, name in enumerate(RULES)
    ]
    buttons.append([
        {"text": "⬅️ Назад", "callback_data": "soc:menu"},
        {"text": "🏠 Главное меню", "callback_data": "soc:menu"}
    ])
    return {"inline_keyboard": buttons}


def back_markup():
    return {"inline_keyboard": [[{"text": "⬅️ Вернуться в меню", "callback_data": "soc:menu"}]]}



def edit_menu(message, text, markup):
    """Обновляет текущее сообщение вместо отправки нового."""
    message_id = message.get("message_id")

    if not message_id:
        raise ValueError("У сообщения отсутствует message_id")

    telegram_api("editMessageText", {
        "chat_id": TG_CHAT_ID,
        "message_id": message_id,
        "text": text,
        "reply_markup": markup,
    })


def send_menu():
    telegram_api("sendMessage", {
        "chat_id": TG_CHAT_ID,
        "text": "🛡 ELK SOC Assistant\nВыбери действие кнопкой ниже.\nУправление статусами пока только через Kibana.",
        "reply_markup": menu_markup(),
    })


def active_alerts_text():
    # Query Elasticsearch, not the local notification history.
    body = {
        "size": MENU_LIMIT,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.workflow_status",
                    "kibana.alert.threshold_result", "host.name",
                    "winlog.event_data.DeviceDescription"],
        "query": {"bool": {"filter": [
            {"terms": {"kibana.alert.rule.name": list(RULES)}},
            {"terms": {"kibana.alert.workflow_status": ["open", "acknowledged"]}},
        ]}},
    }
    response = es_query(body)
    total = response["hits"]["total"]["value"]
    lines = [f"🚨 АКТИВНЫЕ АЛЕРТЫ: {total}", "Последние 8 (открытые и в работе):", ""]
    for hit in response["hits"]["hits"]:
        data = hit["_source"]
        name = field(data, "kibana.alert.rule.name", "Неизвестно")
        host = get_host(data)
        status = field(data, "kibana.alert.workflow_status", "open")
        lines.append(f"• {name} | {host} | {STATUS_NAMES.get(status, status)}")
        lines.append(f"  {format_time(field(data, '@timestamp'))} (UTC+6)")
    if not response["hits"]["hits"]:
        lines.append("Активных алертов нет.")
    return "\n".join(lines)


def action_text(action):
    if action == "stats":
        return stats_text(False)
    if action == "report":
        return stats_text(True)
    if action == "alerts":
        return active_alerts_text()
    if action == "help":
        return ("❓ СПРАВКА\n"
                "Нажми кнопку в меню для просмотра статистики, отчёта или активных алертов.\n"
                "Также работают команды /menu, /stats, /report, /pdf, /csv, /alerts и /help.\n"
                "PDF и CSV: выбери правило и период 24 часа, 7 или 30 дней; до 300 строк.\n"
                "Изменение статусов выполняется только в Kibana.")
    raise ValueError("Неизвестное действие")


def handle_commands(db):
    # Exactly one getUpdates consumer for this Telegram bot.
    updates = telegram_api("getUpdates", {
        "offset": get_offset(db), "timeout": 0,
        "limit": 25, "allowed_updates": ["message", "callback_query"],
    }) or []
    for update in updates:
        update_id = update["update_id"]
        callback = update.get("callback_query")
        msg = (callback or {}).get("message") if callback else update.get("message")
        msg = msg or {}
        sender = (callback or {}).get("from") if callback else msg.get("from")
        sender = sender or {}
        chat = msg.get("chat") or {}
        authorized = (sender.get("id") == ALLOWED_USER_ID
                      and str(chat.get("id")) == str(TG_CHAT_ID)
                      and chat.get("type") == "private")
        try:
            if callback:
                # Telegram expects callback acknowledgement even if unauthorized.
                try:
                    telegram_api("answerCallbackQuery", {
                        "callback_query_id": callback["id"],
                        "text": "Нет доступа" if not authorized else "",
                    })
                except RuntimeError as exc:
                    if "query is too old" in str(exc) or "query ID is invalid" in str(exc):
                        print("Устаревшая кнопка пропущена", flush=True)
                        set_offset(db, update_id + 1)
                        continue
                    else:
                        raise

                if authorized:
                    raw_action = callback.get("data", "")
                    if raw_action == "soc:menu":
                        edit_menu(msg, "🛡 ELK SOC Assistant\nВыбери действие кнопкой ниже.\nУправление статусами только через Kibana.", menu_markup())
                    elif raw_action in ("soc:pdf", "soc:csv"):
                        request_report(raw_action.split(":", 1)[1])
                    elif raw_action == "sel:all":
                        edit_menu(msg, "📄 Общий отчёт\nВыбери период:", report_period_markup(-1))
                    elif raw_action == "sel:rules":
                        edit_menu(msg, "📋 Выбери правило для отчёта:", rule_choice_markup())
                    elif raw_action.startswith("choose:"):
                        i = int(raw_action.split(":")[1]); name = list(RULES)[i]
                        edit_menu(msg, f"📋 Правило: {name}\nВыбери период:", report_period_markup(i))
                    elif raw_action.startswith("back:period:"):
                        i = int(raw_action.split(":")[2])
                        if i < -1 or i >= len(RULES):
                            raise ValueError("Недопустимое правило")
                        name = list(RULES)[i] if i >= 0 else None
                        title = (
                            f"📋 Правило: {name}\nВыбери период:"
                            if name
                            else "📄 Общий отчёт\nВыбери период:"
                        )
                        edit_menu(msg, title, report_period_markup(i))
                    elif raw_action.startswith("period:"):
                        _, i, hours = raw_action.split(":"); i=int(i); hours=int(hours)
                        if hours not in PERIODS or i < -1 or i >= len(RULES): raise ValueError("Недопустимый выбор")
                        edit_menu(msg, f"📄 Экспорт отчёта\nПравило: {list(RULES)[i] if i >= 0 else 'Все разрешённые'}\nПериод: {PERIODS[hours]}\nВыбери формат:", report_format_markup(i,hours))
                    elif raw_action.startswith("export:"):
                        _, fmt, i, hours = raw_action.split(":"); i=int(i); hours=int(hours)
                        if i < -1 or i >= len(RULES): raise ValueError("Недопустимое правило")
                        name = list(RULES)[i] if i >= 0 else None
                        request_report(fmt, hours, name)
                    elif raw_action in ("soc:stats", "soc:report", "soc:alerts", "soc:help"):
                        action = raw_action.split(":", 1)[1]
                        edit_menu(msg, action_text(action), back_markup())
                    else:
                        print("Отклонена неизвестная кнопка", flush=True)
                else:
                    print("Отклонена кнопка от постороннего пользователя", flush=True)
            else:
                command = (msg.get("text") or "").split(maxsplit=1)[0].split("@")[0].lower()
                commands = {"/stats": "stats", "/report": "report",
                            "/alerts": "alerts", "/help": "help"}
                if authorized and command in ("/pdf", "/csv"):
                    request_report(command[1:])
                elif authorized and command in ("/start", "/menu"):
                    send_menu()
                elif authorized and command in commands:
                    telegram_api("sendMessage", {
                        "chat_id": TG_CHAT_ID,
                        "text": action_text(commands[command]),
                        "reply_markup": back_markup(),
                    })
                elif command.startswith("/"):
                    print("Отклонена команда от неразрешённого пользователя/чата", flush=True)
        except Exception as exc:
            # Retry transient failures instead of losing actions.
            print(f"Ошибка кнопки/команды: {type(exc).__name__}: {exc}", flush=True)
            break
        else:
            set_offset(db, update_id + 1)


def get_host(data):
    threshold = field(data, "kibana.alert.threshold_result", {}) or {}
    for term in threshold.get("terms", []):
        if term.get("field") == "host.name":
            return str(term.get("value") or "Не указан")
    return str(field(data, "host.name") or "Не указан")


def alert_kibana_link(data, hit=None):
    """Build a per-alert Kibana URL. Never use an untrusted alert-supplied host."""
    if not KIBANA_URL:
        return None
    base = urllib.parse.urlsplit(KIBANA_URL)
    if base.scheme not in ("http", "https") or not base.netloc or base.username or base.password or base.query or base.fragment:
        return None
    uuid_value = field(data, "kibana.alert.uuid") or (hit or {}).get("_id")
    index_value = (hit or {}).get("_index") or INDEX
    timestamp = field(data, "@timestamp")
    if not uuid_value or not index_value or not timestamp:
        return None
    path = base.path.rstrip("/") + "/app/security/alerts/redirect/" + urllib.parse.quote(str(uuid_value), safe="")
    params = urllib.parse.urlencode({"index": str(index_value), "timestamp": str(timestamp)})
    return urllib.parse.urlunsplit((base.scheme, base.netloc, path, params, ""))


def build_message(data, previous_status=None, hit=None):
    name = field(data, "kibana.alert.rule.name", "Неизвестное правило")
    kind = RULES[name]
    status = field(data, "kibana.alert.workflow_status", "open")
    severity = field(data, "kibana.alert.severity", "не указана")
    timestamp = format_time(field(data, "@timestamp"))
    host = get_host(data)

    if previous_status is None:
        title = {
            "usb": "🔌 ОБНАРУЖЕН USB-НАКОПИТЕЛЬ",
            "login": "🚨 ОБНАРУЖЕНЫ НЕУДАЧНЫЕ ВХОДЫ",
            "office_shell": "🚨 OFFICE ЗАПУСТИЛ КОМАНДНУЮ ОБОЛОЧКУ",
        }.get(kind, "🔔 НОВЫЙ АЛЕРТ БЕЗОПАСНОСТИ")
    else:
        title = {
            "closed": "✅ АЛЕРТ ЗАКРЫТ",
            "acknowledged": "🔎 АЛЕРТ ПРИНЯТ В РАБОТУ",
            "open": "🔄 АЛЕРТ СНОВА ОТКРЫТ",
        }.get(status, "🔔 ИЗМЕНЕНИЕ СТАТУСА АЛЕРТА")

    lines = [title, "", f"📋 Правило: {name}"]
    if kind == "usb":
        device = field(data, "winlog.event_data.DeviceDescription") or "Не указано"
        device_class = field(data, "winlog.event_data.ClassName") or "Не указано"
        lines.extend([
            "🆔 Windows Event ID: 6416",
            f"💾 Устройство: {device}",
            f"🔌 Класс устройства: {device_class}",
        ])
    elif kind == "login":
        count = (field(data, "kibana.alert.threshold_result", {}) or {}).get("count", "Не указано")
        lines.extend(["🆔 Windows Event ID: 4625", f"❌ Неудачных попыток: {count}"])
    elif kind == "office_shell":
        parent = str(field(data, "process.parent.name") or field(data, "winlog.event_data.ParentImage") or "Не указан")
        child = str(field(data, "process.name") or field(data, "winlog.event_data.Image") or "Не указан")
        username = str(field(data, "user.name") or field(data, "winlog.event_data.User") or "Не указан")
        cmd = str(field(data, "process.command_line") or field(data, "winlog.event_data.CommandLine") or "Не указана")
        # Avoid leaking long command lines or exceeding Telegram limits.
        cmd = cmd.replace("\r", " ").replace("\n", " ")[:350]
        lines.extend([
            "🆔 Sysmon Event ID: 1",
            f"📄 Родитель: {parent}",
            f"💻 Дочерний процесс: {child}",
            f"👤 Пользователь: {username}",
            f"⌨️ Командная строка: {cmd}",
        ])
    if kind not in ("usb", "login", "office_shell"):
        lines.append("📝 Детали: " + str(field(data, "kibana.alert.reason") or field(data,"event.code") or "Сработало правило")[:250])
    lines.extend([
        f"🖥 Компьютер: {host}",
        f"🕒 Время создания (UTC+6): {timestamp}",
        f"⚠️ Критичность: {str(severity).upper()}",
        f"📊 Статус: {STATUS_NAMES.get(status, status)}",
    ])
    if previous_status is not None:
        lines.append(f"↪️ Предыдущий статус: {STATUS_NAMES.get(previous_status, previous_status)}")
        changed_at = field(data, "kibana.alert.workflow_status_updated_at")
        if changed_at:
            lines.append(f"🕒 Изменён (UTC+6): {format_time(changed_at)}")
    link = alert_kibana_link(data, hit)
    if link:
        lines.append("🔗 Открыть алерт в Kibana: " + link)
    return "\n".join(lines)


def process_alert(db, hit):
    alert_id = f"{hit['_index']}:{hit['_id']}"
    data = hit["_source"]
    name = field(data, "kibana.alert.rule.name")
    if name not in RULES:
        return
    status = field(data, "kibana.alert.workflow_status", "open")
    row = db.execute("SELECT status FROM alert_states WHERE id=?", (alert_id,)).fetchone()
    previous = row[0] if row else None

    if previous is None:
        # Old sent notifications stay sent; import current status without replay.
        old_sent = db.execute("SELECT 1 FROM sent WHERE id=?", (alert_id,)).fetchone()
        if old_sent:
            with db:
                db.execute("INSERT OR REPLACE INTO alert_states(id,status) VALUES (?,?)", (alert_id, status))
            return
        if send_telegram(build_message(data, hit=hit)):
            with db:
                db.execute("INSERT OR IGNORE INTO sent(id) VALUES (?)", (alert_id,))
                db.execute("INSERT INTO alert_states(id,status) VALUES (?,?)", (alert_id, status))
            print(f"Новый алерт: {name} ({hit['_id'][:12]})", flush=True)
        return

    if previous == status:
        return
    if send_telegram(build_message(data, previous_status=previous, hit=hit)):
        with db:
            db.execute("UPDATE alert_states SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, alert_id))
        print(f"Статус: {name} {previous} -> {status}", flush=True)


def main():
    db = setup_database()

    # Отдельный поток для генерации PDF/CSV.
    # SQLite остаётся только в основном потоке.
    worker = threading.Thread(
        target=report_worker,
        name="soc-report-worker",
        daemon=True
    )
    worker.start()

    print("Обработчик PDF/CSV запущен", flush=True)
    print("ELK Telegram Notifier запущен", flush=True)
    print("Правила: " + ", ".join(RULES), flush=True)
    print(f"Время UTC+6, опрос {POLL_SECONDS} сек.; inline-меню: /menu", flush=True)
    next_alert_poll = 0.0
    while True:
        now = time.monotonic()
        if now >= next_alert_poll:
            try:
                for hit in find_alerts():
                    try:
                        process_alert(db, hit)
                    except Exception as exc:
                        print(f"Ошибка алерта: {type(exc).__name__}: {exc}", flush=True)
            except Exception as exc:
                print(f"Ошибка Elasticsearch: {type(exc).__name__}: {exc}", flush=True)
            next_alert_poll = time.monotonic() + POLL_SECONDS
        try:
            handle_commands(db)
        except Exception as exc:
            print(f"Ошибка Telegram команд: {type(exc).__name__}: {exc}", flush=True)
        time.sleep(COMMAND_POLL_SECONDS)


if __name__ == "__main__":
    main()
