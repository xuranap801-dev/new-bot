import base64
import html
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone

import requests
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def esc(text) -> str:
    return html.escape(str(text))


def clean_domain(raw: str) -> str:
    return raw.replace("https://", "").replace("http://", "").split("/")[0]


def get_reply_or_arg_text(update: Update) -> str:
    """Text after the command, or the text of the replied-to message if no args."""
    parts = update.message.text.split(None, 1)
    if len(parts) > 1 and parts[1].strip():
        return parts[1].strip()
    if update.message.reply_to_message:
        return update.message.reply_to_message.text or update.message.reply_to_message.caption or ""
    return ""


def fetch_ssl_info(domain: str) -> dict:
    """Returns SSL cert info as a dict. Raises on failure — caller should catch."""
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    not_after = cert.get("notAfter", "Unknown")

    days_left = None
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_dt - datetime.utcnow()).days
    except Exception:
        pass

    return {
        "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
        "common_name": subject.get("commonName", "Unknown"),
        "not_after": not_after,
        "days_left": days_left,
    }


def fetch_dns_records(domain: str) -> dict:
    """Returns {record_type: [values]}. Never raises — returns {} on total failure."""
    records = {}
    if DNS_AVAILABLE:
        for record_type in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=8)
                records[record_type] = [str(r) for r in answers]
            except Exception:
                continue
    else:
        try:
            records["A"] = [socket.gethostbyname(domain)]
        except Exception:
            pass
    return records


def fetch_headers_info(url: str):
    """Returns (response, elapsed_ms). Raises on failure — caller should catch."""
    start = time.time()
    resp = requests.get(url, timeout=15, allow_redirects=True)
    elapsed_ms = (time.time() - start) * 1000
    return resp, elapsed_ms


# ---------------------------------------------------------------- /json ----
async def json_format(update: Update, context: ContextTypes.DEFAULT_TYPE):
    raw = get_reply_or_arg_text(update)
    if not raw:
        await update.message.reply_text(
            "Usage: /json <json text>\nOr reply to a message containing JSON with /json"
        )
        return
    try:
        parsed = json.loads(raw)
        pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
    except Exception as e:
        await update.message.reply_text(f"❌ Invalid JSON: {e}")
        return

    if len(pretty) > 3500:
        pretty = pretty[:3500] + "\n... (truncated)"

    await update.message.reply_text(
        f"🧾 <b>Formatted JSON</b>\n<pre>{esc(pretty)}</pre>", parse_mode=ParseMode.HTML
    )


# -------------------------------------------------------------- /base64 ----
async def base64_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if len(args) < 2 or args[0].lower() not in ("encode", "decode"):
        await update.message.reply_text(
            "Usage:\n/base64 encode <text>\n/base64 decode <text>"
        )
        return

    action = args[0].lower()
    text = " ".join(args[1:])
    try:
        if action == "encode":
            result = base64.b64encode(text.encode()).decode()
        else:
            padded = text + "=" * (-len(text) % 4)
            result = base64.b64decode(padded).decode(errors="replace")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
        return

    await update.message.reply_text(
        f"🔐 <b>Base64 {action}d:</b>\n<code>{esc(result)}</code>", parse_mode=ParseMode.HTML
    )


# ----------------------------------------------------------------- /jwt ----
def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


async def jwt_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /jwt <token>")
        return

    token = context.args[0]
    parts = token.split(".")
    if len(parts) < 2:
        await update.message.reply_text("❌ That doesn't look like a valid JWT.")
        return

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        await update.message.reply_text(f"❌ Couldn't decode: {e}")
        return

    exp_note = ""
    if "exp" in payload:
        try:
            exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            status = "🔴 EXPIRED" if exp_time < now else "🟢 valid"
            exp_note = f"\n⏰ <b>Expires:</b> {exp_time.strftime('%Y-%m-%d %H:%M UTC')} ({status})"
        except Exception:
            pass

    text = (
        f"🔑 <b>JWT Decoded</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<b>Header:</b>\n<pre>{esc(json.dumps(header, indent=2))}</pre>\n"
        f"<b>Payload:</b>\n<pre>{esc(json.dumps(payload, indent=2))}</pre>"
        f"{exp_note}\n\n"
        f"⚠️ Signature NOT verified — this only decodes, it doesn't confirm authenticity."
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# --------------------------------------------------------------- /regex ----
async def regex_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    parts = update.message.text.split(None, 1)
    if len(parts) < 2 or "|" not in parts[1]:
        await update.message.reply_text(
            "Usage: /regex <pattern>|<test string>\nExample: /regex \\d+|abc123def456"
        )
        return

    pattern_str, test_str = parts[1].split("|", 1)
    try:
        matches = re.findall(pattern_str, test_str)
    except re.error as e:
        await update.message.reply_text(f"❌ Invalid regex: {e}")
        return

    if not matches:
        await update.message.reply_text("🔍 No matches found.")
        return

    shown = matches[:20]
    matches_text = "\n".join(f"　{i + 1}. {esc(m)}" for i, m in enumerate(shown))
    more_note = f"\n\n... and {len(matches) - 20} more" if len(matches) > 20 else ""
    await update.message.reply_text(
        f"🔍 <b>Regex Matches</b> ({len(matches)} found)\n{matches_text}{more_note}",
        parse_mode=ParseMode.HTML,
    )


# ------------------------------------------------------------- /apitest ----
async def apitest_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text(
            "Usage: /apitest <url>\nOr: /apitest POST <url>\n(GET/POST/PUT/DELETE/PATCH/HEAD supported)"
        )
        return

    if len(args) >= 2 and args[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
        method, url = args[0].upper(), args[1]
    else:
        method, url = "GET", args[0]

    try:
        start = time.time()
        resp = requests.request(method, url, timeout=15)
        elapsed_ms = (time.time() - start) * 1000
    except requests.RequestException as e:
        await update.message.reply_text(f"❌ Request failed: {e}")
        return

    body_preview = resp.text[:800]
    text = (
        f"🌐 <b>API Test — {method}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔗 {esc(url)}\n"
        f"📟 <b>Status:</b> {resp.status_code} {esc(resp.reason)}\n"
        f"⏱️ <b>Response time:</b> {elapsed_ms:.0f} ms\n"
        f"📦 <b>Content-Type:</b> {esc(resp.headers.get('Content-Type', 'unknown'))}\n\n"
        f"<b>Body preview:</b>\n<pre>{esc(body_preview)}</pre>"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ------------------------------------------------------------- /headers ----
async def headers_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /headers <url>")
        return

    url = context.args[0]
    try:
        start = time.time()
        resp = requests.get(url, timeout=15, allow_redirects=True)
        elapsed_ms = (time.time() - start) * 1000
    except requests.RequestException as e:
        await update.message.reply_text(f"❌ Request failed: {e}")
        return

    headers_text = "\n".join(f"　{esc(k)}: {esc(v)}" for k, v in resp.headers.items())
    redirect_note = f"↪️ <b>Redirects:</b> {len(resp.history)}\n" if resp.history else ""

    text = (
        f"📋 <b>Response Headers</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <b>Final URL:</b> {esc(resp.url)}\n"
        f"📟 <b>Status:</b> {resp.status_code}\n"
        f"⏱️ <b>Response time:</b> {elapsed_ms:.0f} ms\n"
        f"{redirect_note}"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<pre>{headers_text}</pre>"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ----------------------------------------------------------------- /ssl ----
async def ssl_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ssl <domain>")
        return

    domain = clean_domain(context.args[0])
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        await update.message.reply_text(f"❌ Couldn't fetch SSL info: {e}")
        return

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    not_before = cert.get("notBefore", "Unknown")
    not_after = cert.get("notAfter", "Unknown")

    expiry_note = ""
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_dt - datetime.utcnow()).days
        expiry_note = " (🔴 EXPIRED)" if days_left < 0 else f" (🟢 {days_left} days left)"
    except Exception:
        pass

    text = (
        f"🔒 <b>SSL Certificate Info</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>Domain:</b> {esc(domain)}\n"
        f"🏢 <b>Issued by:</b> {esc(issuer.get('organizationName', issuer.get('commonName', 'Unknown')))}\n"
        f"📛 <b>Common Name:</b> {esc(subject.get('commonName', 'Unknown'))}\n"
        f"📅 <b>Valid from:</b> {esc(not_before)}\n"
        f"📅 <b>Valid until:</b> {esc(not_after)}{expiry_note}"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ----------------------------------------------------------------- /dns ----
async def dns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /dns <domain>")
        return

    domain = clean_domain(context.args[0])
    lines = []

    if DNS_AVAILABLE:
        for record_type in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=8)
                values = ", ".join(esc(str(r)) for r in answers)
                lines.append(f"　<b>{record_type}:</b> {values}")
            except Exception:
                continue
    else:
        try:
            ip = socket.gethostbyname(domain)
            lines.append(f"　<b>A:</b> {esc(ip)}")
        except Exception as e:
            await update.message.reply_text(f"❌ Couldn't resolve domain: {e}")
            return

    if not lines:
        await update.message.reply_text("❌ No DNS records found (or domain doesn't exist).")
        return

    text = f"🧭 <b>DNS Records — {esc(domain)}</b>\n━━━━━━━━━━━━━━━━━━\n" + "\n".join(lines)
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)
