import sqlite3
from datetime import datetime

DB_PATH = "bot_data.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            joined_at TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            link TEXT,
            searched_at TEXT
        )"""
    )
    conn.commit()
    conn.close()


def add_user(user_id, username, first_name):
    """Adds the user if not already present. Returns True if this is a brand-new user."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO users (user_id, username, first_name, joined_at) VALUES (?, ?, ?, ?)",
        (user_id, username, first_name, datetime.now().isoformat()),
    )
    is_new = c.rowcount > 0
    conn.commit()
    conn.close()
    return is_new


def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id FROM users")
    rows = [row[0] for row in c.fetchall()]
    conn.close()
    return rows


def log_search(user_id, link):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO searches (user_id, link, searched_at) VALUES (?, ?, ?)",
        (user_id, link, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM searches")
    total_searches = c.fetchone()[0]
    conn.close()
    return total_users, total_searches
