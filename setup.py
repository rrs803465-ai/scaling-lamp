#!/usr/bin/env python3
"""
DxdPanel — first-run setup.
Creates the admin account. Users cannot self-provision VPSes;
only admins grant them via the admin panel.
"""
import sqlite3, getpass, time
from werkzeug.security import generate_password_hash

DB = "panel.db"

def init():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        signup_ip TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        recovery_code_hash TEXT,
        recovery_code_shown INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        container_id TEXT NOT NULL,
        ssh_command TEXT,
        status TEXT DEFAULT 'creating',
        creator_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_regen INTEGER DEFAULT 0,
        kvm_enabled INTEGER DEFAULT 0,
        cpu_cores INTEGER DEFAULT 4,
        ram_gb INTEGER DEFAULT 4,
        disk_gb INTEGER DEFAULT 80,
        node_id INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id=1),
        message TEXT, active INTEGER DEFAULT 0, updated_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS panel_config (
        key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL,
        shared_secret TEXT NOT NULL,
        label TEXT,
        connected_at INTEGER NOT NULL,
        last_seen INTEGER DEFAULT 0,
        vps_count INTEGER DEFAULT 0,
        cpu_cores INTEGER DEFAULT 0,
        ram_mb INTEGER DEFAULT 0,
        disk_gb INTEGER DEFAULT 0,
        bootstrapped INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    """)
    con.execute("INSERT OR IGNORE INTO broadcast(id,message,active,updated_at) VALUES(1,'',0,0)")
    con.commit()

    c.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if c.fetchone()[0] == 0:
        print("\n╔══════════════════════════════╗")
        print("║   DxdPanel — First Run       ║")
        print("╚══════════════════════════════╝\n")
        username = input("  Admin username: ").strip()
        while not username:
            username = input("  Cannot be empty: ").strip()
        password = getpass.getpass("  Admin password: ")
        while len(password) < 6:
            password = getpass.getpass("  Min 6 chars: ")
        con.execute(
            "INSERT INTO users(username,password,signup_ip,is_admin,created_at,recovery_code_shown)"
            " VALUES(?,?,?,1,?,1)",
            (username, generate_password_hash(password), "127.0.0.1", int(time.time()))
        )
        con.commit()
        print(f"\n  ✓ Admin '{username}' created.")
    else:
        print("\n  Admin already exists — skipping.")

    con.close()
    print("  Run with: python3 app.py\n")

if __name__ == "__main__":
    init()
