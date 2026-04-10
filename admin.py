import sqlite3
from flask import Blueprint, request, session, redirect, url_for, render_template

admin_bp = Blueprint("admin", __name__)

DATABASE_PATH = "mediaportal.db"


def get_db():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


@admin_bp.route("/admin")
def admin_dashboard():
    # vulnerability: Broken Access Control, there is no check that the requesting user
    # has the 'admin' role (or even that they are logged in). 
    # CWE: CWE-285 (Improper Authorisation)

    db = get_db()
    cursor = db.cursor()

    filter_role = request.args.get("role", "")

    if filter_role:
        # vulnerability: SQL Injection on admin query, the role filter parameter is
        # concatenated directly into the SQL statement. 
        # CWE: CWE-89 (Improper Neutralisation of Special Elements used in an SQL Command)
        query = "SELECT * FROM users WHERE role = '" + filter_role + "'"
        cursor.execute(query)
    else:
        cursor.execute("SELECT * FROM users")

    # vulnerability: Information Disclosure of Password Hashes, all user records,
    # including their hashed passwords, are fetched and passed directly to the template.
    # CWE: CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
    users = cursor.fetchall()
    db.close()

    return render_template("admin.html", users=users)


@admin_bp.route("/admin/delete-user", methods=["POST"])
def delete_user():
    # vulnerability: Broken Access Control, same as /admin: no role or session check.
    # Any unauthenticated request can delete user accounts by POSTing to this endpoint.
    # CWE: CWE-285 (Improper Authorisation)

    user_id = request.form.get("user_id", "")

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()

    return redirect(url_for("admin.admin_dashboard"))
