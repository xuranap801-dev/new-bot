# Telegram Link-Checker Bot — Setup Guide

## Ye bot kya karta hai
- `/start` → welcome dashboard (naam, user ID, username, time, chat type) + **"USE HERE 😎"** button jo group me le jaata hai
- `/check <link>` → link ke redirects follow karke final destination, service type, **file info (type/size)**, aur **VirusTotal safety scan (safe/suspicious/malicious)** batata hai
- `/check` **as a reply** → kisi link wale message ko reply karke sirf `/check` bhejo, bot us message me se link nikal ke check kar lega
- `/dev` → developer contact (`@liesworlds`)
- `/admin` → **sirf owner** ko dikhta hai — total users + total link searches
- `/broadcast <message>` → **sirf owner** use kar sakta hai, sab stored users ko ek saath message bhejta hai
- Jab bhi koi **naya** user `/start` karega, **owner ko turant notification** milegi (naam, ID, username, time)
- Agar koi bot ko **DM me** direct link bhej de (bina `/check` ke), bot English me reply karta hai: use group me karo

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
