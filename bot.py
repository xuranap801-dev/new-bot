import asyncio
import logging
import re
from datetime import datetime
from urllib.parse import urlparse

import requests
from playwright.async_api import async_playwright
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

import config
import database as db
import devtools

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

URL_REGEX = re.compile(r"https?://[^\s]+")

# Known domains -> human readable description (extend this dict as needed)
KNOWN_SERVICES = {
    "youtube.com": "YouTube video/channel link",
    "youtu.be": "YouTube video link (short)",
    "instagram.com": "Instagram post/profile/reel link",
    "drive.google.com": "Google Drive file/folder link",
    "mediafire.com": "MediaFire file hosting link",
    "terabox.com": "TeraBox cloud storage link",
    "t.me": "Telegram channel/group/user link",
    "bit.ly": "Bitly shortened link",
    "tinyurl.com": "TinyURL shortened link",
    "shorte.st": "Shorte.st ad-shortener link",
    "linkvertise.com": "Linkvertise ad-shortener link",
    "adfly.com": "Adf.ly ad-shortener link",
    "ouo.io": "Ouo.io ad-shortener link",
    "gplinks.in": "GPLinks ad-shortener link",
    "gplinks.co": "GPLinks ad-shortener link",
    "shrinkme.io": "Shrinkme ad-shortener link",
    "exe.io": "Exe.io ad-shortener link",
    "clk.sh": "Clk.sh ad-shortener link",
}

# Domains that use a JS/timer-based ad-wall — the simple HTTP method usually can't
# get past these, so /check falls back to headless-browser automation for them.
AD_WALL_KEYWORDS = [
    "gplinks", "linkvertise", "shrinkme", "shrinke.me", "ouo.io",
    "adfly", "shorte.st", "exe.io", "clk.sh", "droplink", "clicksfly",
]


def looks_like_ad_wall(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    return any(keyword in domain for keyword in AD_WALL_KEYWORDS)


def identify_service(url: str) -> str:
    domain = urlparse(url).netloc.lower().replace("www.", "")
    for key, desc in KNOWN_SERVICES.items():
        if key in domain:
            return desc
    return f"Unrecognized service ({domain})" if domain else "Unknown"


CONTINUE_BUTTON_TEXTS = [
    "get link", "continue", "click here", "proceed", "verify",
    "unlock link", "generate link", "get content", "skip ad",
]

# Limits how many headless browsers run at once, regardless of how many
# /check requests come in simultaneously — prevents RAM exhaustion.
BROWSER_SEMAPHORE = asyncio.Semaphore(config.MAX_CONCURRENT_BROWSERS)


async def resolve_with_browser(url: str, max_clicks: int = 4, timer_wait_ms: int = 6000):
    """Loads the page in a real headless browser, waits out any countdown timer,
    and clicks through common 'continue/get link' buttons to reach the final URL.
    Returns (chain, final_url, error). Cannot solve captchas/human-verification steps."""
    chain = [url]
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        page = await browser.new_page(user_agent="Mozilla/5.0 LinkCheckerBot/1.0")
        try:
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")

            for _ in range(max_clicks):
                await page.wait_for_timeout(timer_wait_ms)  # let any countdown finish

                clicked = False
                for text in CONTINUE_BUTTON_TEXTS:
                    try:
                        btn = page.get_by_text(text, exact=False)
                        if await btn.count() > 0:
                            try:
                                async with page.expect_navigation(timeout=8000):
                                    await btn.first.click()
                            except Exception:
                                await btn.first.click()
                            clicked = True
                            break
                    except Exception:
                        continue

                if page.url not in chain:
                    chain.append(page.url)
                if not clicked:
                    break

            final_url = page.url
        except Exception as e:
            await browser.close()
            return chain, None, f"Browser automation failed: {e}"

        await browser.close()
        return chain, final_url, None


def resolve_link(url: str, max_hops: int = 10):
    """Follow HTTP redirects + basic meta-refresh redirects to find the final URL.
    Note: JS-only redirect pages (countdown ad walls that need a click/JS execution)
    can't be resolved this way - that would need a headless browser."""
    chain = [url]
    current = url
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 LinkCheckerBot/1.0"})
    last_headers = {}

    for _ in range(max_hops):
        try:
            resp = session.get(current, allow_redirects=True, timeout=10)
        except requests.RequestException as e:
            return chain, current, f"Error fetching link: {e}", {}

        final = resp.url
        last_headers = resp.headers
        if final != current:
            chain.append(final)
        current = final

        match = re.search(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]+;\s*url=([^"\']+)["\']',
            resp.text,
            re.IGNORECASE,
        )
        if match:
            next_url = match.group(1).strip()
            if next_url not in chain:
                chain.append(next_url)
                current = next_url
                continue
        break

    return chain, current, None, last_headers


def vt_check_url(url: str):
    """Submits the URL to VirusTotal and returns the detection stats dict, or None if unavailable."""
    if not config.VIRUSTOTAL_API_KEY:
        return None

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15,
        )
        if submit.status_code not in (200, 201):
            return None
        analysis_id = submit.json()["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15,
        )
        if result.status_code != 200:
            return None
        return result.json()["data"]["attributes"]["stats"]
    except Exception:
        logger.exception("VirusTotal check failed")
        return None


def format_file_size(size_str):
    try:
        size = int(size_str)
    except (TypeError, ValueError):
        return "Unknown"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    is_new = db.add_user(user.id, user.username, user.first_name)

    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    if is_new and user.id != config.OWNER_ID:
        try:
            await context.bot.send_message(
                chat_id=config.OWNER_ID,
                text=(
                    f"🆕 <b>New user started the bot!</b>\n\n"
                    f"👤 Name: {user.first_name}\n"
                    f"🆔 ID: <code>{user.id}</code>\n"
                    f"🔗 Username: @{user.username if user.username else 'N/A'}\n"
                    f"🕒 Time: {now}"
                ),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            logger.exception("Could not notify owner about new user")

    text = (
        f"✨ <b>W E L C O M E</b> ✨\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"😎 Hey <b>{user.first_name}</b>, glad to have you!\n\n"
        f"🆔 <b>User ID:</b> <code>{user.id}</code>\n"
        f"👤 <b>Username:</b> @{user.username if user.username else 'N/A'}\n"
        f"🕒 <b>Joined at:</b> {now}\n"
        f"💬 <b>Chat type:</b> {update.effective_chat.type}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔍 I'm your personal <b>link-checker</b> bot — I sniff out\n"
        f"where any link <i>really</i> leads, right inside the group.\n\n"
        f"⚡ Just type: <code>/check &lt;link&gt;</code>\n\n"
        f"👇 Tap below to jump into the action 👇"
    )

    keyboard = InlineKeyboardMarkup(
        [[InlineKeyboardButton("🚀 USE HERE 😎", url=config.GROUP_LINK)]]
    )

    await update.message.reply_text(text, reply_markup=keyboard, parse_mode=ParseMode.HTML)


async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = None

    if context.args:
        url = context.args[0]
    elif update.message.reply_to_message:
        replied_text = (
            update.message.reply_to_message.text
            or update.message.reply_to_message.caption
            or ""
        )
        found = URL_REGEX.search(replied_text)
        if found:
            url = found.group(0)

    if not url:
        await update.message.reply_text(
            "🤔 <b>Oops!</b>\nUsage: <code>/check &lt;link&gt;</code>\n"
            "Or just reply to a message containing a link with <code>/check</code> 🔗",
            parse_mode=ParseMode.HTML,
        )
        return

    if not URL_REGEX.match(url):
        await update.message.reply_text(
            "🚫 That doesn't look like a valid link.\nIt must start with <code>http://</code> or <code>https://</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    msg = await update.message.reply_text("🔍✨ Scanning link, hold tight...")

    chain, final_url, error, headers = resolve_link(url)
    db.log_search(update.effective_user.id, url)

    if error:
        await msg.edit_text(f"❌ <b>Failed!</b>\n{error}", parse_mode=ParseMode.HTML)
        return

    used_browser = False
    if looks_like_ad_wall(url) or looks_like_ad_wall(final_url):
        if BROWSER_SEMAPHORE.locked():
            await msg.edit_text(
                "⏳ Ad-wall detected — other checks are running first, you're queued..."
            )
        async with BROWSER_SEMAPHORE:
            await msg.edit_text(
                "🤖 Ad-wall detected — using browser automation to get past the timer, "
                "this can take 15-30s..."
            )
            browser_chain, browser_final, browser_error = await resolve_with_browser(final_url)
        if browser_error is None and browser_final and browser_final != final_url:
            chain += [u for u in browser_chain if u not in chain]
            final_url = browser_final
            used_browser = True
        await msg.edit_text("🔍✨ Finishing up...")

    service = identify_service(final_url)
    hops_text = "\n".join(f"　{i + 1}️⃣ {u}" for i, u in enumerate(chain))
    bypass_note = "🤖 <b>Bypassed via browser automation</b>\n" if used_browser else ""

    # File info from HTTP headers (content type + size, if it's a direct file link)
    content_type = headers.get("Content-Type", "Unknown").split(";")[0]
    content_length = headers.get("Content-Length")
    file_text = (
        f"📄 <b>Content type:</b> {content_type}\n"
        f"📦 <b>Size:</b> {format_file_size(content_length)}\n"
    )

    # Safety scan via VirusTotal
    await msg.edit_text("🔍✨ Link found, running safety scan...")
    vt_stats = vt_check_url(final_url)

    if vt_stats is None:
        safety_text = (
            f"🛡️ <b>Safety scan:</b> unavailable\n"
            f"(no VirusTotal API key set, or scan failed — treat unknown links with caution)"
        )
    else:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        harmless = vt_stats.get("harmless", 0)
        undetected = vt_stats.get("undetected", 0)

        if malicious > 0:
            verdict = "🔴 <b>MALICIOUS</b> — flagged by security engines, do NOT open!"
        elif suspicious > 0:
            verdict = "🟡 <b>SUSPICIOUS</b> — proceed with caution"
        else:
            verdict = "🟢 <b>No detections</b> — looks safe (not a 100% guarantee)"

        safety_text = (
            f"🛡️ <b>Safety scan (VirusTotal):</b>\n"
            f"{verdict}\n"
            f"　☠️ Malicious: {malicious} | ⚠️ Suspicious: {suspicious} | ✅ Harmless: {harmless} | ❔ Undetected: {undetected}"
        )

    result = (
        f"🔗 <b>L I N K   R E P O R T</b> 🔗\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📥 <b>Original:</b>\n{url}\n\n"
        f"🎯 <b>Final destination:</b>\n{final_url}\n\n"
        f"🏷️ <b>Likely service:</b> {service}\n"
        f"{bypass_note}"
        f"{file_text}"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"{safety_text}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🧭 <b>Redirect chain:</b>\n{hops_text}\n\n"
        f"✅ Scan complete!"
    )
    await msg.edit_text(result, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def dev(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"👨‍💻 <b>Developer</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🛠️ Built &amp; maintained by: {config.DEVELOPER_USERNAME}\n"
        f"💬 Hit up for bugs, ideas, or just to say hi!",
        parse_mode=ParseMode.HTML,
    )


async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != config.OWNER_ID:
        return  # non-owners get no response at all

    total_users, total_searches = db.get_stats()
    text = (
        f"📊 <b>A D M I N   P A N E L</b> 📊\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👥 <b>Total users joined:</b> {total_users}\n"
        f"🔎 <b>Total links searched:</b> {total_searches}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔐 Owner-only view"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != config.OWNER_ID:
        return  # silently ignore for non-owners

    text = update.message.text.partition(" ")[2].strip()
    if not text:
        await update.message.reply_text(
            "📢 <b>Broadcast</b>\nUsage: <code>/broadcast &lt;message&gt;</code>\n\n"
            "Example:\n<code>/broadcast New update is live, check it out in the group! 🚀</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    user_ids = db.get_all_users()
    status_msg = await update.message.reply_text(
        f"📢✨ Broadcasting to {len(user_ids)} users..."
    )

    sent, failed = 0, 0
    for uid in user_ids:
        try:
            await context.bot.send_message(chat_id=uid, text=text, parse_mode=ParseMode.HTML)
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.05)  # avoid hitting Telegram rate limits

    await status_msg.edit_text(
        f"✅ <b>Broadcast complete!</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📨 Sent: {sent}\n"
        f"⚠️ Failed (blocked bot etc.): {failed}",
        parse_mode=ParseMode.HTML,
    )


async def tools_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        f"🧰 <b>D E V   T O O L S</b> 🧰\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <code>/check &lt;link&gt;</code> — resolve, bypass &amp; scan a link\n"
        f"🧾 <code>/json &lt;text&gt;</code> — pretty-print JSON\n"
        f"🔐 <code>/base64 encode|decode &lt;text&gt;</code>\n"
        f"🔑 <code>/jwt &lt;token&gt;</code> — decode a JWT\n"
        f"🔍 <code>/regex &lt;pattern&gt;|&lt;text&gt;</code> — test a regex\n"
        f"🌐 <code>/apitest [METHOD] &lt;url&gt;</code> — hit an API\n"
        f"📋 <code>/headers &lt;url&gt;</code> — response headers + timing\n"
        f"🔒 <code>/ssl &lt;domain&gt;</code> — SSL certificate info\n"
        f"🧭 <code>/dns &lt;domain&gt;</code> — DNS records\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👨‍💻 <code>/dev</code> — developer contact"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def handle_private_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private":
        return
    text = update.message.text or ""
    if URL_REGEX.search(text):
        await update.message.reply_text(
            f"🙅‍♂️ <b>Wrong place, friend!</b>\n"
            f"I don't work here in DMs.\n\n"
            f"👉 Use me inside the group: {config.GROUP_LINK}",
            parse_mode=ParseMode.HTML,
        )


def main():
    db.init_db()
    app = ApplicationBuilder().token(config.BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("check", check))
    app.add_handler(CommandHandler("dev", dev))
    app.add_handler(CommandHandler("admin", admin))
    app.add_handler(CommandHandler("broadcast", broadcast))
    app.add_handler(CommandHandler("tools", tools_list))
    app.add_handler(CommandHandler("json", devtools.json_format))
    app.add_handler(CommandHandler("base64", devtools.base64_cmd))
    app.add_handler(CommandHandler("jwt", devtools.jwt_cmd))
    app.add_handler(CommandHandler("regex", devtools.regex_cmd))
    app.add_handler(CommandHandler("apitest", devtools.apitest_cmd))
    app.add_handler(CommandHandler("headers", devtools.headers_cmd))
    app.add_handler(CommandHandler("ssl", devtools.ssl_cmd))
    app.add_handler(CommandHandler("dns", devtools.dns_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_private_message))

    logger.info("Bot starting...")
    app.run_polling()


if __name__ == "__main__":
    main()
