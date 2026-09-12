"""
Warstwa tozsamosci uzytkownikow i logu audytowego dla cybersec-agent.

Dlaczego to istnieje: narzedzie potrafi wykonywac realne ataki (sqlmap,
hydra, nmap) na wskazane cele. Bez powiazania kazdego uzycia z konkretna,
zidentyfikowana osoba nie ma mozliwosci egzekwowania odpowiedzialnosci
prawnej/dyscyplinarnej za nadużycie narzedzia. Ta warstwa wymusza logowanie
przed uzyciem i zapisuje pelny slad: kto, kiedy, jakie narzedzie, na jaki cel.

Baza: SQLite, plik w /app/data (wolumen trwaly, przezywa restart kontenera).
Hasla: nigdy w czystej postaci - haszowane przez bcrypt.
"""
from __future__ import annotations

import sqlite3
import secrets
import datetime
from pathlib import Path
from contextlib import contextmanager

import bcrypt

DB_PATH = Path("/app/data/users.db")

SESSION_LIFETIME_HOURS = 8


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Tworzy tabele jesli jeszcze nie istnieja. Bezpieczne do wielokrotnego
    wywolania (np. przy kazdym starcie orchestratora)."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_admin INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tool_name TEXT,
                target TEXT,
                thread_id TEXT,
                status TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            """
        )
    print(f"auth_db: baza zainicjalizowana ({DB_PATH})")


def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def create_user(first_name: str, last_name: str, email: str, password: str) -> dict:
    """Zaklada nowe konto. Rzuca sqlite3.IntegrityError jesli e-mail juz istnieje."""
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (first_name, last_name, email, password_hash, created_at, is_active) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (first_name, last_name, email.lower().strip(), password_hash, _now()),
        )
        return {"id": cur.lastrowid, "email": email}


def verify_login(email: str, password: str) -> dict | None:
    """Sprawdza haslo. Zwraca dane uzytkownika jesli poprawne, inaczej None.
    Zapisuje probe (udana/nieudana) do audit_log."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1",
            (email.lower().strip(),),
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO audit_log (user_id, timestamp, event_type, status) VALUES (NULL, ?, 'login_failed', 'blocked')",
                (_now(),),
            )
            return None

        password_ok = bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8"))

        conn.execute(
            "INSERT INTO audit_log (user_id, timestamp, event_type, status) VALUES (?, ?, ?, ?)",
            (row["id"], _now(), "login" if password_ok else "login_failed", "success" if password_ok else "blocked"),
        )

        if not password_ok:
            return None

        return dict(row)


def set_admin(email: str, is_admin: bool = True) -> bool:
    """Recznie nadaje/odbiera uprawnienia administratora. Uzywane z linii
    polecen przy pierwszym uruchomieniu systemu - nie ma jeszcze
    samoobslugowego mechanizmu nadawania rol (swiadoma decyzja: rola
    administratora nie powinna byc nadawana przez sam interfejs www)."""
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE users SET is_admin = ? WHERE email = ?",
            (1 if is_admin else 0, email.lower().strip()),
        )
        return cur.rowcount > 0


def get_user_by_email(email: str) -> dict | None:
    """Zwraca dane uzytkownika po adresie e-mail, bez sprawdzania hasla.
    Uzywane wewnetrznie do zapisu logu audytowego, gdy mamy juz zweryfikowany
    e-mail z aktywnej sesji (nie do logowania)."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1",
            (email.lower().strip(),),
        ).fetchone()
        return dict(row) if row else None


def create_session(user_id: int) -> str:
    """Tworzy nowa sesje, zwraca token do zapisania w przegladarce (cookie)."""
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(hours=SESSION_LIFETIME_HOURS)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, token, now.isoformat(), expires.isoformat(), now.isoformat()),
        )
    return token


def get_user_by_session(token: str) -> dict | None:
    """Sprawdza czy token sesji jest wazny i zwraca dane uzytkownika. Odswieza
    last_seen_at. Zwraca None jesli token nieprawidlowy lub wygasl."""
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT users.* FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND sessions.expires_at > ? AND users.is_active = 1
            """,
            (token, _now()),
        ).fetchone()

        if row is None:
            return None

        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token = ?",
            (_now(), token),
        )
        return dict(row)


def log_tool_call(user_id: int, tool_name: str, target: str, thread_id: str, status: str = "success") -> None:
    """Zapisuje uzycie narzedzia do logu audytowego. To jest wywolywane przy
    kazdym faktycznym wywolaniu narzedzia ofensywnego/audytowego."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (user_id, timestamp, event_type, tool_name, target, thread_id, status) "
            "VALUES (?, ?, 'tool_call', ?, ?, ?, ?)",
            (user_id, _now(), tool_name, target, thread_id, status),
        )


def get_audit_log(limit: int = 100, user_email: str | None = None) -> list[dict]:
    """Zwraca ostatnie wpisy logu audytowego, opcjonalnie przefiltrowane
    po adresie e-mail uzytkownika. Do przegladania 'kto co robil'."""
    with _connect() as conn:
        if user_email:
            rows = conn.execute(
                """
                SELECT audit_log.*, users.email, users.first_name, users.last_name
                FROM audit_log
                LEFT JOIN users ON users.id = audit_log.user_id
                WHERE users.email = ?
                ORDER BY audit_log.timestamp DESC
                LIMIT ?
                """,
                (user_email.lower().strip(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT audit_log.*, users.email, users.first_name, users.last_name
                FROM audit_log
                LEFT JOIN users ON users.id = audit_log.user_id
                ORDER BY audit_log.timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
