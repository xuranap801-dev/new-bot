# Telegram Link-Checker Bot — Setup Guide

## Ye bot kya karta hai
- `/start` → welcome dashboard (naam, user ID, username, time, chat type) + **"USE HERE 😎"** button jo group me le jaata hai
- `/check <link>` → link ke redirects follow karke final destination, service type, **file info (type/size)**, aur **VirusTotal safety scan (safe/suspicious/malicious)** batata hai
  - Agar link GPLinks/Linkvertise/Shrinkme jaisi **timer-wali ad-wall** ho, bot automatically **headless browser (Playwright)** se timer ka wait karke aur button click karke bypass try karta hai
- `/check` **as a reply** → kisi link wale message ko reply karke sirf `/check` bhejo, bot us message me se link nikal ke check kar lega
- `/dev` → developer contact (`@liesworlds`)
- `/admin` → **sirf owner** ko dikhta hai — total users + total link searches
- `/broadcast <message>` → **sirf owner** use kar sakta hai, sab stored users ko ek saath message bhejta hai
- Jab bhi koi **naya** user `/start` karega, **owner ko turant notification** milegi (naam, ID, username, time)
- Agar koi bot ko **DM me** direct link bhej de (bina `/check` ke), bot English me reply karta hai: use group me karo

## 🤖 Ad-wall bypass setup (Playwright)
GPLinks jaisi timer-based ad-wall sites ke liye ek real headless browser chahiye. Do extra steps:

1. `pip install -r requirements.txt` (isme ab `playwright` bhi shamil hai)
2. Browser binary install karo (**ye step alag se karna zaroori hai**):
   ```bash
   python -m playwright install --with-deps chromium
   ```

**Railway pe deploy karte waqt**: Settings → **Build Command** me ye daalo:
```
pip install -r requirements.txt && python -m playwright install --with-deps chromium
```

**Limitations (honest):**
- **Captcha / "select all traffic lights" jaisi human-verification steps automate nahi ho sakti** — koi bhi tool ye nahi kar sakta.
- Headless browser **RAM/CPU-heavy** hai. Isliye `config.py` me `MAX_CONCURRENT_BROWSERS = 1` set hai — agar ek saath 10 log ad-wall links bhejenge, wo crash nahi karega, balki **queue lag jaayegi** (ek-ek karke process honge, thoda slow ho jaayega). Value badhane se pehle apne server ki RAM check kar lena.
- Har `/check` jisme ad-wall detect ho, ~15-30 seconds lag sakte hain (timer wait + button click + navigation).
- Sirf timer/button-click type ad-walls hi cover hoti hain; naye/unusual ad-shorteners jinke button text list me nahi hai, unke liye `CONTINUE_BUTTON_TEXTS` list me naye text add karne padenge (`bot.py` me).

## 🛡️ Safety scan setup (VirusTotal)
Malicious/safe check ke liye ek **free** VirusTotal API key chahiye:
1. https://www.virustotal.com/gui/join-us pe account banao
2. Profile icon → **API Key** copy karo
3. `config.py` me `VIRUSTOTAL_API_KEY = "yaha_paste_karo"`

**Limits (free tier)**: ~4 requests/minute, 500/day — heavy group use me thoda slow ho sakta hai. Key na ho to bot "safety scan unavailable" dikha dega, baaki sab (redirect trace, file info) waisi hi kaam karega.

**Honest limitation**: VirusTotal 70+ antivirus engines ka crowd-sourced result hai — bahut accurate hai but 100% guarantee nahi. Bilkul naya/unknown malware kabhi "0 detections" bhi dikha sakta hai. Isse security signal lo, final judgment nahi.

## ⚠️ Zaroori note — button color
Telegram Bot API me inline button ka **color customize karna possible nahi hai**. Button hamesha user ke Telegram app theme ke default color me hi dikhega. Isliye maine sirf emoji (😎) add kiya hai, "green" wala part technically nahi ho sakta.

## Setup Steps

1. **Bot banao**: [@BotFather](https://t.me/BotFather) ko `/newbot` bhejo, token milega.
2. **Apna Telegram ID nikalo**: [@userinfobot](https://t.me/userinfobot) ko message karo.
3. `config.py` khol ke fill karo:
   ```python
   BOT_TOKEN = "..."       # BotFather wala token
   OWNER_ID = 123456789    # tumhara numeric ID
   GROUP_LINK = "https://t.me/tumhara_group"
   ```
4. Dependencies install karo:
   ```bash
   pip install -r requirements.txt
   ```
5. Bot chalao:
   ```bash
   python bot.py
   ```

## Files
- `bot.py` — main bot logic
- `database.py` — SQLite (users + searches ka data `bot_data.db` me save hota hai)
- `config.py` — apni settings
- `requirements.txt` — dependencies

## Limitations (honest note)
- `/check` normal HTTP redirects aur basic meta-refresh redirects follow kar leta hai.
- Kuch ad-link sites (jo JavaScript / countdown / captcha use karte hain) is simple method se bypass nahi hongi — unke liye headless browser (Selenium/Playwright) chahiye hoga, jo isme include nahi hai.
- Deploy karne ke liye VPS/Railway/Render jaisi jagah 24x7 chalate rehna hoga (`app.run_polling()` tab tak hi chalega jab tak process live hai).
