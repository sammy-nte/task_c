import hashlib
import sqlite3
from flask import Blueprint, request, session, redirect, url_for, render_template

auth_bp = Blueprint("auth", __name__)

DATABASE_PATH = "mediaportal.db"


def get_db():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


# vulnerability: MD5 used for password hashing, MD5 is a cryptographic hash function,
# not a password hashing algorithm. It has no salt, is extremely fast to compute, and
# is trivially reversible via rainbow tables or GPU-accelerated brute force.
# CWE: CWE-916 (Use of Password Hash With Insufficient Computational Effort)
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # vulnerability: No rate limiting on login, there is no mechanism to throttle
        # or lock accounts after repeated failed login attempts. 
        # CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)

        hashed = hash_password(password)

        db = get_db()
        cursor = db.cursor()

        # vulnerability: SQL Injection on login query, the username is inserted directly
        # into the SQL string using string concatenation. 
        # CWE: CWE-89 (Improper Neutralisation of Special Elements used in an SQL Command)
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed + "'"
        cursor.execute(query)
        user = cursor.fetchone()
        db.close()

        if user:
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["user_id"] = user["id"]
            return redirect(url_for("records.view_records"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
