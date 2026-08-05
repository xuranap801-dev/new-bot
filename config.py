# === Bot Configuration ===
# Neeche wali sab values apni khud ki daal do

BOT_TOKEN = "8702055600:AAHE-jydRoSUQpJMFdFrP7_cMRurkfa2zAk"
OWNER_ID = 8790645158                       # apna Telegram numeric user ID (e.g. from @userinfobot)
GROUP_LINK = "https://t.me/+U9X-xebCj301MWQ1"
DEVELOPER_USERNAME = "@liesworlds"

# Free API key from https://www.virustotal.com/gui/join-us (sign up -> profile -> API key)
# Iske bina safety scan (malicious/safe check) kaam nahi karega
VIRUSTOTAL_API_KEY = ""

# Max number of headless-browser (Playwright) instances allowed to run at the same
# time — protects low-RAM hosting (like Railway free tier) from crashing when many
# ad-wall links are checked at once. Extra requests just wait their turn in a queue.
MAX_CONCURRENT_BROWSERS = 1
