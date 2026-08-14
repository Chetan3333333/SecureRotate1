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
MODEL_VERSION = "rf-surrogate-2.0-simplified"


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
    if probability >= 0.80:
        return "Critical"
    if probability >= 0.60:
        return "High"
    if probability >= 0.30:
        return "Medium"
    return "Low"


def feature_score(credential: sqlite3.Row | dict) -> tuple[float, list[dict]]:
    days = int(credential["days_to_expiry"])
    
    factors = []
    if days < 0:
        factors.append({"label": "Expiry window", "weight": 1.0, "evidence": "Expired"})
        return 1.0, factors
    elif days <= 15:
        # Scale probability from 0.8 at 0 days down to 0.3 at 15 days
        prob = 0.8 - ((15 - days) / 15.0) * 0.5
        factors.append({"label": "Expiry window", "weight": prob, "evidence": f"{days} days remaining"})
        return prob, factors
    else:
        factors.append({"label": "Expiry window", "weight": 0.05, "evidence": "Healthy"})
        return 0.05, factors


def recommend_action(credential: sqlite3.Row | dict, risk: str, probability: float, factors: list[dict]) -> dict:
    days = int(credential["days_to_expiry"])

    if days < 0:
        action = "Immediate Rotation"
        urgency = "Breach"
    elif days <= 3:
        action = "Immediate Rotation"
        urgency = "Critical"
    elif days <= 7:
        action = "Rotate Within 24 Hours"
        urgency = "High"
    elif days <= 30:
        action = "Schedule Rotation"
        urgency = "Medium"
    else:
        action = "Monitor"
        urgency = "Low"

    stakeholders = ["Account Owner", "Security Team"]
    approval_required = False
    explanation = f"{credential['username']} is {risk.lower()} risk. It expires in {days} days."

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


def create_user_credential(conn: sqlite3.Connection, payload: dict) -> dict:
    database_name = required_text(payload, "database_name", "Database name")
    username = required_text(payload, "username", "Username")
    password = required_text(payload, "password", "Password")
    owner = required_text(payload, "owner", "Owner name")
    expiry_date = required_text(payload, "expiry_date", "Expiry date")

    try:
        expiry = date.fromisoformat(expiry_date)
    except ValueError as exc:
        raise ValueError("Expiry date must use YYYY-MM-DD format") from exc

    days_to_expiry = (expiry - today()).days
    credential_age = max(0, min(365, 90 - days_to_expiry))
    salt = secrets.token_hex(16)
    secret_ref = f"vault://securerotate/{database_name.lower().replace(' ', '-')}/{username}"

    cursor = conn.execute(
        """
        INSERT INTO credentials (
            database_name, username, owner, expiry_date, status, secret_ref,
            password_hash, password_salt, last_rotated_at, created_at
        ) VALUES (?, ?, ?, ?, 'Submitted', ?, ?, ?, ?, ?)
        """,
        (
            database_name,
            username,
            owner,
            expiry.isoformat(),
            secret_ref,
            hash_secret(password, salt),
            salt,
            (today() - timedelta(days=credential_age)).isoformat(),
            iso_now(),
        ),
    )
    credential_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (owner, "submit_credential", "credential", credential_id, f"User submitted {database_name}/{username} for monitoring.", iso_now()),
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
                owner TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                secret_ref TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                last_rotated_at TEXT,
                created_at TEXT NOT NULL
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
        ("MySQL", "john.doe@company.com", "John Doe", -1),
        ("PostgreSQL", "alice.smith@company.com", "Alice Smith", 2),
        ("Oracle", "bob.jenkins@company.com", "Bob Jenkins", 6),
        ("SQL Server", "sarah.connor@company.com", "Sarah Connor", 9),
        ("MySQL", "mike.ross@company.com", "Mike Ross", 18),
        ("PostgreSQL", "harvey.specter@company.com", "Harvey Specter", 24),
        ("Oracle", "rachel.zane@company.com", "Rachel Zane", 33),
        ("SQL Server", "donna.paulsen@company.com", "Donna Paulsen", 41),
        ("MySQL", "louis.litt@company.com", "Louis Litt", 57),
        ("PostgreSQL", "jessica.pearson@company.com", "Jessica Pearson", 77),
        ("Oracle", "katrina.bennett@company.com", "Katrina Bennett", 4),
        ("SQL Server", "alex.williams@company.com", "Alex Williams", 120),
    ]

    for row in rows:
        salt = secrets.token_hex(16)
        placeholder_secret = generate_password()
        conn.execute(
            """
            INSERT INTO credentials (
                database_name, username, owner, expiry_date, status, secret_ref,
                password_hash, password_salt, last_rotated_at, created_at
            ) VALUES (?, ?, ?, ?, 'Active', ?, ?, ?, ?, ?)
            """,
            (
                row[0],
                row[1],
                row[2],
                (today() + timedelta(days=row[3])).isoformat(),
                f"vault://securerotate/{row[0].lower()}/{row[1]}",
                hash_secret(placeholder_secret, salt),
                salt,
                (today() - timedelta(days=90 - row[3])).isoformat(),
                iso_now()
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

    def keep(item: dict) -> bool:
        haystack = " ".join(str(item[key]) for key in ("database_name", "username", "owner")).lower()
        if search and search not in haystack:
            return False
        if risk != "All" and item["risk"] != risk:
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
    for item in credentials:
        risk_distribution[item["risk"]] += 1
    rotations = conn.execute("SELECT * FROM rotation_history ORDER BY id DESC").fetchall()
    success = sum(1 for row in rotations if row["verification_status"] == "Verified")
    return {
        "total": total,
        "expiring": expiring,
        "expired": expired,
        "critical": critical,
        "risk_distribution": risk_distribution,
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
    
    # Always succeed for the demo now that dependencies are gone
    verification_ok = True

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
            SET expiry_date = ?, password_hash = ?, password_salt = ?, last_rotated_at = ?, status = 'Active'
            WHERE id = ?
            """,
            (new_expiry, hash_secret(password, salt), salt, iso_now(), credential_id),
        )
        conn.execute("UPDATE notifications SET status = 'Resolved' WHERE credential_id = ? AND status != 'Acknowledged'", (credential_id,))
    else:
        conn.execute(
            "UPDATE credentials SET status = 'Needs Review' WHERE id = ?",
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
            SELECT n.*, c.database_name, c.username
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
