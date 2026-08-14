from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import string
import time
from datetime import date, datetime, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, send_file


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
DB_PATH = ROOT / "securerotate.db"
MODEL_VERSION = "rf-surrogate-1.0"


def today() -> date:
    return date.today()


def iso_now() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def risk_rank(risk: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(risk, 0)


def classify(probability: float) -> str:
    if probability >= 0.82:
        return "Critical"
    if probability >= 0.62:
        return "High"
    if probability >= 0.38:
        return "Medium"
    return "Low"


def feature_score(credential: sqlite3.Row | dict) -> tuple[float, list[dict]]:
    days = int(credential["days_to_expiry"])
    env = credential["environment"]
    privilege = credential["privilege_level"]
    deps = int(credential["dependency_count"])
    failed = int(credential["failed_logins"])
    previous_failures = int(credential["previous_rotation_failures"])
    age = int(credential["credential_age"])
    usage = int(credential["usage_frequency"])
    criticality = int(credential["criticality"])
    account_type = credential["account_type"]

    factors = []

    def add(label: str, weight: float, evidence: str) -> None:
        if weight > 0:
            factors.append({"label": label, "weight": round(weight, 3), "evidence": evidence})

    expiry_weight = 0.0
    if days < 0:
        expiry_weight = 0.33
    elif days <= 3:
        expiry_weight = 0.28
    elif days <= 7:
        expiry_weight = 0.22
    elif days <= 15:
        expiry_weight = 0.13
    elif days <= 30:
        expiry_weight = 0.07
    add("Expiry window", expiry_weight, f"{days} days remaining")

    env_weight = {"Production": 0.18, "Staging": 0.08, "Development": 0.02}.get(env, 0.04)
    add("Environment criticality", env_weight, env)

    privilege_weight = {"Admin": 0.17, "Write": 0.11, "Read": 0.03}.get(privilege, 0.05)
    add("Privilege level", privilege_weight, privilege)

    dep_weight = min(deps * 0.025, 0.15)
    add("Application dependencies", dep_weight, f"{deps} dependent services")

    failed_weight = min(failed * 0.018, 0.12)
    add("Failed login signal", failed_weight, f"{failed} recent failures")

    history_weight = min(previous_failures * 0.05, 0.1)
    add("Rotation history", history_weight, f"{previous_failures} previous rotation failures")

    age_weight = 0.1 if age >= 120 else 0.06 if age >= 90 else 0.02 if age >= 60 else 0
    add("Credential age", age_weight, f"{age} days old")

    usage_weight = min(usage / 1000 * 0.09, 0.11)
    add("Usage frequency", usage_weight, f"{usage} daily authentications")

    criticality_weight = min(criticality * 0.025, 0.125)
    add("Business criticality", criticality_weight, f"score {criticality}/5")

    service_weight = 0.05 if account_type == "Service" else 0.015
    add("Account type", service_weight, account_type)

    raw_score = sum(item["weight"] for item in factors)
    probability = min(0.97, max(0.08, raw_score * 0.82))
    factors.sort(key=lambda item: item["weight"], reverse=True)
    return probability, factors[:5]


def recommend_action(credential: sqlite3.Row | dict, risk: str, probability: float, factors: list[dict]) -> dict:
    days = int(credential["days_to_expiry"])
    env = credential["environment"]
    privilege = credential["privilege_level"]
    deps = int(credential["dependency_count"])
    account_type = credential["account_type"]

    if days < 0:
        action = "Immediate Rotation"
        urgency = "Breach"
    elif risk == "Critical" or (days <= 3 and env == "Production"):
        action = "Immediate Rotation"
        urgency = "Critical"
    elif risk == "High" or days <= 7:
        action = "Rotate Within 24 Hours" if env == "Production" or privilege == "Admin" else "Rotate Within 72 Hours"
        urgency = "High"
    elif risk == "Medium" or days <= 30:
        action = "Schedule Rotation"
        urgency = "Medium"
    else:
        action = "Monitor"
        urgency = "Low"

    stakeholders = ["Account Owner"]
    if urgency in {"Medium", "High", "Critical", "Breach"}:
        stakeholders.append("DBA")
    if env == "Production" or risk in {"High", "Critical"}:
        stakeholders.append("Application Owner")
    if risk == "Critical" or days < 0 or privilege == "Admin":
        stakeholders.append("Security Team")

    approval_required = env == "Production" and (account_type == "Service" or privilege == "Admin" or deps >= 3)
    explanation = (
        f"{credential['username']} is {risk.lower()} risk at {round(probability * 100)}% because "
        f"{factors[0]['label'].lower()} is the dominant driver ({factors[0]['evidence']})."
    )
    if days <= 7:
        explanation += " It is inside the seven-day expiry notification window."
    if approval_required:
        explanation += " Production dependency controls require approval before rotation."

    return {
        "action": action,
        "urgency": urgency,
        "stakeholders": stakeholders,
        "approval_required": approval_required,
        "explanation": explanation,
    }


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+" for c in password)
        ):
            return password


def hash_secret(secret: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt.encode("utf-8"), 600_000)
    return digest.hex()


def required_text(payload: dict, key: str, label: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"{label} is required")
    return value


def bounded_int(payload: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    raw = payload.get(key, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def create_user_credential(conn: sqlite3.Connection, payload: dict) -> dict:
    database_name = required_text(payload, "database_name", "Database name")
    username = required_text(payload, "username", "Username")
    password = required_text(payload, "password", "Password")
    owner = required_text(payload, "owner", "Owner name")
    app_owner = required_text(payload, "app_owner", "Application owner")
    expiry_date = required_text(payload, "expiry_date", "Expiry date")

    try:
        expiry = date.fromisoformat(expiry_date)
    except ValueError as exc:
        raise ValueError("Expiry date must use YYYY-MM-DD format") from exc

    account_type = payload.get("account_type", "Service")
    if account_type not in {"Service", "Human"}:
        account_type = "Service"
    environment = payload.get("environment", "Development")
    if environment not in {"Production", "Staging", "Development"}:
        environment = "Development"
    privilege_level = payload.get("privilege_level", "Read")
    if privilege_level not in {"Read", "Write", "Admin"}:
        privilege_level = "Read"

    dependency_count = bounded_int(payload, "dependency_count", 0, 0, 20)
    criticality = bounded_int(payload, "criticality", 3, 1, 5)
    usage_frequency = bounded_int(payload, "usage_frequency", 120, 0, 2000)
    days_to_expiry = (expiry - today()).days
    credential_age = max(0, min(365, 90 - days_to_expiry))
    salt = secrets.token_hex(16)
    secret_ref = f"vault://securerotate/user-submissions/{database_name.lower().replace(' ', '-')}/{username}"

    cursor = conn.execute(
        """
        INSERT INTO credentials (
            database_name, username, account_type, environment, privilege_level, owner, app_owner,
            dba, security_contact, dependency_count, failed_logins, previous_rotation_failures,
            credential_age, usage_frequency, criticality, expiry_date, status, secret_ref,
            password_hash, password_salt, last_rotated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Admin Queue', 'Security Team', ?, 0, 0, ?, ?, ?, ?, 'Submitted', ?, ?, ?, ?)
        """,
        (
            database_name,
            username,
            account_type,
            environment,
            privilege_level,
            owner,
            app_owner,
            dependency_count,
            credential_age,
            usage_frequency,
            criticality,
            expiry.isoformat(),
            secret_ref,
            hash_secret(password, salt),
            salt,
            (today() - timedelta(days=credential_age)).isoformat(),
        ),
    )
    credential_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (owner, "submit_credential", "credential", credential_id, f"User submitted {database_name}/{username} for admin risk review.", iso_now()),
    )
    refresh_notifications(conn)
    item = next(credential for credential in enriched_credentials(conn) if credential["id"] == credential_id)
    return {
        "id": credential_id,
        "risk": item["risk"],
        "risk_probability": item["risk_probability"],
        "recommendation": item["recommendation"],
        "days_to_expiry": item["days_to_expiry"],
    }


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                database_name TEXT NOT NULL,
                username TEXT NOT NULL,
                account_type TEXT NOT NULL,
                environment TEXT NOT NULL,
                privilege_level TEXT NOT NULL,
                owner TEXT NOT NULL,
                app_owner TEXT NOT NULL,
                dba TEXT NOT NULL,
                security_contact TEXT NOT NULL,
                dependency_count INTEGER NOT NULL,
                failed_logins INTEGER NOT NULL,
                previous_rotation_failures INTEGER NOT NULL,
                credential_age INTEGER NOT NULL,
                usage_frequency INTEGER NOT NULL,
                criticality INTEGER NOT NULL,
                expiry_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                secret_ref TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                last_rotated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER NOT NULL,
                recipients TEXT NOT NULL,
                message TEXT NOT NULL,
                channel TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT,
                FOREIGN KEY (credential_id) REFERENCES credentials(id)
            );

            CREATE TABLE IF NOT EXISTS rotation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                verification_status TEXT NOT NULL,
                details TEXT NOT NULL,
                FOREIGN KEY (credential_id) REFERENCES credentials(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        count = conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"]
        if count:
            refresh_notifications(conn)
            return

        seed_credentials(conn)
        refresh_notifications(conn)


def seed_credentials(conn: sqlite3.Connection) -> None:
    rows = [
        ("Aurora-Payroll", "payroll_admin", "Service", "Production", "Admin", "Meera Iyer", "Raj Malhotra", "Nina Shah", "SOC Desk", 7, 4, 1, 118, 820, 5, -1),
        ("Postgres-CoreBank", "loan_service_app", "Service", "Production", "Write", "Sanjay Rao", "Aarav Menon", "Nina Shah", "SOC Desk", 5, 1, 0, 86, 610, 5, 2),
        ("Customer360", "crm_sync_user", "Service", "Production", "Write", "Isha Kapoor", "Leena Nair", "Dev Patel", "SOC Desk", 4, 2, 1, 96, 540, 4, 6),
        ("Inventory-DB", "warehouse_writer", "Service", "Staging", "Write", "Karan Mehta", "Priya S", "Dev Patel", "SOC Desk", 3, 0, 0, 71, 250, 3, 9),
        ("Analytics-Mart", "bi_reader", "Human", "Production", "Read", "Anika Das", "Rhea Sen", "Nina Shah", "SOC Desk", 2, 0, 0, 64, 140, 3, 18),
        ("HR-Records", "hr_ops", "Human", "Production", "Write", "Vikram Joshi", "Maya Roy", "Nina Shah", "SOC Desk", 2, 3, 0, 78, 190, 4, 24),
        ("DevLab", "dev_admin", "Human", "Development", "Admin", "Farah Khan", "Om Prakash", "Dev Patel", "SOC Desk", 1, 0, 0, 42, 55, 2, 33),
        ("Payments-Replica", "replica_reader", "Service", "Production", "Read", "Neil Thomas", "Aarav Menon", "Nina Shah", "SOC Desk", 2, 0, 0, 35, 400, 4, 41),
        ("Marketing-CDP", "segment_loader", "Service", "Staging", "Write", "Tara Bose", "Rhea Sen", "Dev Patel", "SOC Desk", 2, 1, 0, 52, 220, 2, 57),
        ("QA-Orders", "qa_runner", "Service", "Development", "Write", "Rohan Pillai", "Om Prakash", "Dev Patel", "SOC Desk", 1, 0, 0, 21, 85, 1, 77),
        ("FraudGraph", "fraud_detect_app", "Service", "Production", "Write", "Anika Das", "Leena Nair", "Nina Shah", "SOC Desk", 6, 5, 2, 132, 900, 5, 4),
        ("Reporting-Archive", "archive_reader", "Human", "Staging", "Read", "Meera Iyer", "Rhea Sen", "Dev Patel", "SOC Desk", 0, 0, 0, 30, 35, 1, 120),
    ]

    for row in rows:
        salt = secrets.token_hex(16)
        placeholder_secret = generate_password()
        conn.execute(
            """
            INSERT INTO credentials (
                database_name, username, account_type, environment, privilege_level, owner, app_owner,
                dba, security_contact, dependency_count, failed_logins, previous_rotation_failures,
                credential_age, usage_frequency, criticality, expiry_date, status, secret_ref,
                password_hash, password_salt, last_rotated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?)
            """,
            (
                *row[:-1],
                (today() + timedelta(days=row[-1])).isoformat(),
                f"vault://securerotate/{row[0].lower()}/{row[1]}",
                hash_secret(placeholder_secret, salt),
                salt,
                (today() - timedelta(days=row[12])).isoformat(),
            ),
        )

    conn.execute(
        "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("system", "seed_demo", "workspace", 0, "Loaded synthetic database credential metadata for the SecureRotate demo.", iso_now()),
    )


def refresh_notifications(conn: sqlite3.Connection) -> None:
    rows = enriched_credentials(conn)
    existing = {
        row["credential_id"]
        for row in conn.execute("SELECT credential_id FROM notifications WHERE status != 'Resolved'").fetchall()
    }
    for credential in rows:
        if credential["days_to_expiry"] <= 7 and credential["id"] not in existing:
            recipients = ", ".join(credential["recommendation"]["stakeholders"])
            message = (
                f"{credential['database_name']} / {credential['username']} reaches expiry in "
                f"{credential['days_to_expiry']} days. Recommended action: {credential['recommendation']['action']}."
            )
            conn.execute(
                """
                INSERT INTO notifications(credential_id, recipients, message, channel, status, created_at)
                VALUES (?, ?, ?, 'Email + In-App', 'Sent', ?)
                """,
                (credential["id"], recipients, message, iso_now()),
            )
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                ("notification-engine", "notify_stakeholders", "credential", credential["id"], message, iso_now()),
            )


def row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


def enriched_credentials(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM credentials ORDER BY expiry_date ASC").fetchall()
    result = []
    for row in rows:
        item = row_to_dict(row)
        expiry = date.fromisoformat(item["expiry_date"])
        item["days_to_expiry"] = (expiry - today()).days
        probability, factors = feature_score(item)
        risk = classify(probability)
        recommendation = recommend_action(item, risk, probability, factors)
        item["risk_probability"] = round(probability, 3)
        item["risk"] = risk
        item["risk_factors"] = factors
        item["recommendation"] = recommendation
        item["stakeholders"] = recommendation["stakeholders"]
        item["password_hash"] = "redacted"
        item["password_salt"] = "redacted"
        result.append(item)
    return result


def apply_filters(credentials: list[dict], query: dict) -> list[dict]:
    search = query.get("search", [""])[0].lower().strip()
    risk = query.get("risk", ["All"])[0]
    environment = query.get("environment", ["All"])[0]
    account_type = query.get("account_type", ["All"])[0]

    def keep(item: dict) -> bool:
        haystack = " ".join(str(item[key]) for key in ("database_name", "username", "owner", "app_owner", "environment")).lower()
        if search and search not in haystack:
            return False
        if risk != "All" and item["risk"] != risk:
            return False
        if environment != "All" and item["environment"] != environment:
            return False
        if account_type != "All" and item["account_type"] != account_type:
            return False
        return True

    return [item for item in credentials if keep(item)]


def summary_payload(conn: sqlite3.Connection, query: dict) -> dict:
    credentials = apply_filters(enriched_credentials(conn), query)
    total = len(credentials)
    expiring = sum(1 for item in credentials if 0 <= item["days_to_expiry"] <= 7)
    expired = sum(1 for item in credentials if item["days_to_expiry"] < 0)
    critical = sum(1 for item in credentials if item["risk"] == "Critical")
    risk_distribution = {risk: 0 for risk in ["Low", "Medium", "High", "Critical"]}
    env_distribution = {env: 0 for env in ["Production", "Staging", "Development"]}
    for item in credentials:
        risk_distribution[item["risk"]] += 1
        env_distribution[item["environment"]] += 1
    rotations = conn.execute("SELECT * FROM rotation_history ORDER BY id DESC").fetchall()
    success = sum(1 for row in rotations if row["verification_status"] == "Verified")
    return {
        "total": total,
        "expiring": expiring,
        "expired": expired,
        "critical": critical,
        "risk_distribution": risk_distribution,
        "environment_distribution": env_distribution,
        "rotation_success": success,
        "model_version": MODEL_VERSION,
        "generated_at": iso_now(),
    }


def recommendation_payload(conn: sqlite3.Connection, query: dict) -> list[dict]:
    credentials = apply_filters(enriched_credentials(conn), query)
    ordered = sorted(credentials, key=lambda item: (risk_rank(item["risk"]), item["risk_probability"], -item["days_to_expiry"]), reverse=True)
    return [
        {
            "credential_id": item["id"],
            "database_name": item["database_name"],
            "username": item["username"],
            "environment": item["environment"],
            "risk": item["risk"],
            "risk_probability": item["risk_probability"],
            "days_to_expiry": item["days_to_expiry"],
            **item["recommendation"],
            "top_factors": item["risk_factors"],
        }
        for item in ordered
    ]


def analytics_payload(conn: sqlite3.Connection, query: dict) -> dict:
    credentials = apply_filters(enriched_credentials(conn), query)
    buckets = [
        ("Expired", lambda item: item["days_to_expiry"] < 0),
        ("0-7 days", lambda item: 0 <= item["days_to_expiry"] <= 7),
        ("8-15 days", lambda item: 8 <= item["days_to_expiry"] <= 15),
        ("16-30 days", lambda item: 16 <= item["days_to_expiry"] <= 30),
        ("31+ days", lambda item: item["days_to_expiry"] > 30),
    ]
    expiry_buckets = [{"label": label, "value": sum(1 for item in credentials if fn(item))} for label, fn in buckets]
    factor_totals: dict[str, float] = {}
    for item in credentials:
        for factor in item["risk_factors"]:
            factor_totals[factor["label"]] = factor_totals.get(factor["label"], 0) + factor["weight"]
    top_factors = sorted(
        [{"label": key, "value": round(value, 3)} for key, value in factor_totals.items()],
        key=lambda item: item["value"],
        reverse=True,
    )[:6]
    rotations = [row_to_dict(row) for row in conn.execute("SELECT * FROM rotation_history ORDER BY id DESC").fetchall()]
    return {"expiry_buckets": expiry_buckets, "top_factors": top_factors, "rotations": rotations}


def rotate_credential(conn: sqlite3.Connection, credential_id: int, actor: str) -> dict:
    credential = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if not credential:
        raise ValueError("Credential not found")

    item = row_to_dict(credential)
    item["days_to_expiry"] = (date.fromisoformat(item["expiry_date"]) - today()).days
    probability, factors = feature_score(item)
    risk = classify(probability)
    recommendation = recommend_action(item, risk, probability, factors)
    if recommendation["approval_required"] and not actor:
        raise PermissionError("Approval is required for this production credential")

    started = iso_now()
    conn.execute(
        """
        INSERT INTO rotation_history(credential_id, requested_by, status, started_at, verification_status, details)
        VALUES (?, ?, 'Running', ?, 'Pending', ?)
        """,
        (credential_id, actor or "demo-admin", started, "Generated a strong replacement secret and staged vault update."),
    )
    history_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    password = generate_password()
    salt = secrets.token_hex(16)
    new_expiry = (today() + timedelta(days=90)).isoformat()
    time.sleep(0.35)
    verification_ok = int(credential["dependency_count"]) < 8

    status = "Completed" if verification_ok else "Failed"
    verification = "Verified" if verification_ok else "Failed"
    details = (
        "Password rotated through controlled demo connector, secret hash stored, and connectivity verified."
        if verification_ok
        else "Rotation staged, but dependency verification failed. Previous secret retained."
    )

    if verification_ok:
        conn.execute(
            """
            UPDATE credentials
            SET expiry_date = ?, credential_age = 0, previous_rotation_failures = 0, failed_logins = 0,
                password_hash = ?, password_salt = ?, last_rotated_at = ?, status = 'Active'
            WHERE id = ?
            """,
            (new_expiry, hash_secret(password, salt), salt, iso_now(), credential_id),
        )
        conn.execute("UPDATE notifications SET status = 'Resolved' WHERE credential_id = ? AND status != 'Acknowledged'", (credential_id,))
    else:
        conn.execute(
            "UPDATE credentials SET previous_rotation_failures = previous_rotation_failures + 1, status = 'Needs Review' WHERE id = ?",
            (credential_id,),
        )

    conn.execute(
        """
        UPDATE rotation_history
        SET status = ?, completed_at = ?, verification_status = ?, details = ?
        WHERE id = ?
        """,
        (status, iso_now(), verification, details, history_id),
    )
    conn.execute(
        "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (actor or "demo-admin", "rotate_credential", "credential", credential_id, details, iso_now()),
    )
    refresh_notifications(conn)
    return {"history_id": history_id, "status": status, "verification_status": verification, "details": details}


app = Flask(__name__, static_folder="public")

@app.route("/")
def serve_index():
    return send_file(PUBLIC / "login.html")

@app.route("/admin")
def serve_admin():
    return send_file(PUBLIC / "index.html")

@app.route("/user")
def serve_user():
    return send_file(PUBLIC / "user.html")

@app.route("/<path:filename>")
def serve_static(filename):
    if (PUBLIC / filename).exists():
        return send_from_directory(PUBLIC, filename)
    return "Not Found", 404

def get_query_dict():
    return {k: request.args.getlist(k) for k in request.args.keys()}

@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.json or {}
    email = payload.get("email", "")
    password = payload.get("password", "")
    if email == "admin@securedb.com" and password == "admin123":
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/summary", methods=["GET"])
def api_summary():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(summary_payload(conn, get_query_dict()))

@app.route("/api/credentials", methods=["GET"])
def api_credentials_list():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(apply_filters(enriched_credentials(conn), get_query_dict()))

@app.route("/api/credentials/<int:credential_id>", methods=["GET"])
def api_credential_detail(credential_id):
    with connect() as conn:
        refresh_notifications(conn)
        match = next((item for item in enriched_credentials(conn) if item["id"] == credential_id), None)
        if match:
            return jsonify(match)
        return jsonify({"error": "Credential not found"}), 404

@app.route("/api/recommendations", methods=["GET"])
def api_recommendations():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(recommendation_payload(conn, get_query_dict()))

@app.route("/api/notifications", methods=["GET"])
def api_notifications():
    with connect() as conn:
        refresh_notifications(conn)
        rows = conn.execute(
            """
            SELECT n.*, c.database_name, c.username, c.environment
            FROM notifications n
            JOIN credentials c ON c.id = n.credential_id
            ORDER BY n.id DESC
            """
        ).fetchall()
        return jsonify([row_to_dict(row) for row in rows])

@app.route("/api/audit", methods=["GET"])
def api_audit():
    with connect() as conn:
        refresh_notifications(conn)
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 80").fetchall()
        return jsonify([row_to_dict(row) for row in rows])

@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(analytics_payload(conn, get_query_dict()))

@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    payload = request.json or {}
    try:
        with connect() as conn:
            result = rotate_credential(conn, int(payload["credential_id"]), payload.get("approved_by", "demo-admin"))
        return jsonify(result)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/credentials", methods=["POST"])
def api_credentials_create():
    payload = request.json or {}
    try:
        with connect() as conn:
            result = create_user_credential(conn, payload)
        return jsonify(result), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/notifications/<int:notification_id>/ack", methods=["POST"])
def api_notifications_ack(notification_id):
    payload = request.json or {}
    try:
        with connect() as conn:
            conn.execute(
                "UPDATE notifications SET status = 'Acknowledged', acknowledged_at = ? WHERE id = ?",
                (iso_now(), notification_id),
            )
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (payload.get("actor", "demo-admin"), "acknowledge_notification", "notification", notification_id, "Stakeholder acknowledged expiry alert.", iso_now()),
            )
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/demo/reset", methods=["POST"])
def api_demo_reset():
    try:
        with connect() as conn:
            conn.executescript(
                """
                DROP TABLE IF EXISTS notifications;
                DROP TABLE IF EXISTS rotation_history;
                DROP TABLE IF EXISTS audit_logs;
                DROP TABLE IF EXISTS credentials;
                """
            )
        init_db()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    init_db()
    print(f"SecureRotate running at http://{host}:{port}")
    app.run(host=host, port=port, debug=True, use_reloader=False)

if __name__ == "__main__":
    run(os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "8000")))
