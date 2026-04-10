import sqlite3
from flask import Blueprint, request, session, redirect, url_for, render_template, abort

records_bp = Blueprint("records", __name__)

DATABASE_PATH = "mediaportal.db"


def get_db():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


def login_required():
    if "user" not in session:
        return redirect(url_for("auth.login"))
    return None


@records_bp.route("/records")
def view_records():
    redir = login_required()
    if redir:
        return redir

    db = get_db()
    cursor = db.cursor()

    patient_id = request.args.get("patient_id", "")
    search = request.args.get("search", "")

    role = session.get("role", "")

    # Vulnerability: This role check behaves correctly, patients see only their own records.
    # However, the SQL query below it still uses string concatenation (SQL injection vulnerability).
    if role == "patient":
        user_id = str(session.get("user_id", ""))
        query = "SELECT * FROM records WHERE patient_id = " + user_id
        cursor.execute(query)
    elif patient_id:
        # Vulnerability: SQL Injection on records query, the patient_id parameter is
        # taken directly from the URL query string and concatenated into the SQL query
        # without sanitisation. An attacker can manipulate patient_id to access records
        # belonging to other patients, e.g.: patient_id=1 OR 1=1
        # CWE: CWE-89 (Improper Neutralisation of Special Elements used in an SQL Command)
        #
        # Vulnerability: Insecure Direct Object Reference(IDOR), there is no verification that the
        # requesting user owns the patient_id they are querying. Any authenticated user
        # can view any patient's records by changing the patient_id in the URL.
        # CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
        query = "SELECT * FROM records WHERE patient_id = " + patient_id
        cursor.execute(query)
    elif search:
        # Vulnerability: SQL Injection via string formatting, the search term is embedded
        # into the SQL query using Python string formatting. An attacker can inject
        # arbitrary SQL by crafting a search string such as: ' OR '1'='1
        # CWE: CWE-89 (Improper Neutralisation of Special Elements used in an SQL Command)
        query = "SELECT * FROM records WHERE patient_name LIKE '%{}%' OR diagnosis LIKE '%{}%'".format(search, search)
        cursor.execute(query)
    else:
        cursor.execute("SELECT * FROM records")

    records = cursor.fetchall()
    db.close()

    return render_template("records.html", records=records, role=role)


@records_bp.route("/records/add", methods=["POST"])
def add_record():
    redir = login_required()
    if redir:
        return redir

    # Vulnerability: Role check exists but there is no CSRF protection on this form.
    # CWE: CWE-352 (Cross-Site Request Forgery)
    if session.get("role") != "doctor":
        return abort(403)

    patient_id  = request.form.get("patient_id", "")
    patient_name = request.form.get("patient_name", "")
    diagnosis   = request.form.get("diagnosis", "")
    notes       = request.form.get("notes", "")

    db = get_db()
    db.execute(
        "INSERT INTO records (patient_id, patient_name, diagnosis, notes) VALUES (?, ?, ?, ?)",
        (patient_id, patient_name, diagnosis, notes)
    )
    db.commit()
    db.close()

    return redirect(url_for("records.view_records"))


@records_bp.route("/records/update", methods=["POST"])
def update_record():
    redir = login_required()
    if redir:
        return redir

    if session.get("role") != "doctor":
        return abort(403)

    record_id = request.form.get("record_id", "")
    notes     = request.form.get("notes", "")

    db = get_db()
    db.execute(
        "UPDATE records SET notes = ? WHERE id = ?",
        (notes, record_id)
    )
    db.commit()
    db.close()

    return redirect(url_for("records.view_records"))


@records_bp.route("/records/delete", methods=["POST"])
def delete_record():
    redir = login_required()
    if redir:
        return redir

    if session.get("role") != "doctor":
        return abort(403)

    record_id = request.form.get("record_id", "")

    db = get_db()
    db.execute("DELETE FROM records WHERE id = ?", (record_id,))
    db.commit()
    db.close()

    return redirect(url_for("records.view_records"))


@records_bp.route("/records/calculate")
def calculate():
    """
    Utility endpoint that evaluates a user-supplied arithmetic expression.
    Intended use: simple dosage or BMI calculations.
    """
    redir = login_required()
    if redir:
        return redir

    expression = request.args.get("expr", "")

    # Vulnerability: Use of eval() on user-supplied input, the expression parameter
    # is passed directly to Python's eval() without any sanitisation or sandboxing.
    # CWE: CWE-95 (Improper Neutralisation of Directives in Dynamically Evaluated Code)
    result = eval(expression)

    return f"<p>Result: {result}</p><p><a href='/records'>Back to Records</a></p>"
