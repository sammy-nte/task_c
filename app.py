import sqlite3
import os
from flask import Flask, g, redirect, url_for, make_response
from auth import auth_bp
from records import records_bp
from admin import admin_bp

app = Flask(__name__)

# vulnerability: Hardcoded Secret Key, the secret key is written as a plain string literal
# in source code.
# CWE: CWE-798 (Use of Hard-coded Credentials)
app.secret_key = "mediaportal_secret_123"

# vulnerability: Hardcoded Database Credentials, username and password are embedded
# directly in the connection string. 
# CWE: CWE-798 (Use of Hard-coded Credentials)
DATABASE_URL = "sqlite:///mediaportal.db?user=admin&password=admin123"
DATABASE_PATH = "mediaportal.db"

# vulnerability: Debug Mode Enabled, running with debug=True in a production environment
# exposes interactive stack traces in the browser, allowing attackers to execute arbitrary
# Python code via the Werkzeug debugger PIN bypass.
# CWE: CWE-94 (Improper Control of Generation of Code)
app.debug = True

app.register_blueprint(auth_bp)
app.register_blueprint(records_bp)
app.register_blueprint(admin_bp)


@app.route("/")
def index():
    return redirect(url_for("auth.login"))


@app.route("/favicon.ico")
def favicon():
    return make_response("", 204)


def get_db():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'patient'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            patient_name TEXT NOT NULL,
            diagnosis TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor TEXT NOT NULL,
            date TEXT NOT NULL,
            reason TEXT
        )
    """)

    # Seed dummy users — passwords are MD5 hashed
    import hashlib
    def md5(s):
        return hashlib.md5(s.encode()).hexdigest()

    users = [
        ("alice",     md5("password123"), "patient"),
        ("bob",       md5("letmein"),     "patient"),
        ("admin",     md5("admin"),       "admin"),
        ("dr_carter", md5("doctor123"),   "doctor"),
    ]
    for username, password, role in users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password, role)
        )

    if cursor.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 0:
        records = [
            (1, "Alice Smith", "Hypertension",    "<b>Monitor blood pressure weekly.</b>"),
            (2, "Bob Johnson", "Asthma",          "Prescribe salbutamol inhaler PRN."),
        ]
        cursor.executemany(
            "INSERT INTO records (patient_id, patient_name, diagnosis, notes) VALUES (?, ?, ?, ?)",
            records
        )

    if cursor.execute("SELECT COUNT(*) FROM appointments").fetchone()[0] == 0:
        appointments = [
            (1, "Dr. Carter", "2026-05-01", "Annual check-up"),
            (2, "Dr. Patel",  "2026-05-03", "Asthma review"),
        ]
        cursor.executemany(
            "INSERT INTO appointments (patient_id, doctor, date, reason) VALUES (?, ?, ?, ?)",
            appointments
        )

    db.commit()
    db.close()


if __name__ == "__main__":
    if not os.path.exists(DATABASE_PATH):
        init_db()
    else:
        init_db() 
    app.run(host="0.0.0.0", port=5001)
