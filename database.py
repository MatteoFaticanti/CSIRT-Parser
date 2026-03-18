import sqlite3
import json
import logging
from models import Bollettino

DB_PATH = "csirt_data.db"


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute('''
            CREATE TABLE IF NOT EXISTS bollettini (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                titolo              TEXT NOT NULL,
                url                 TEXT UNIQUE NOT NULL,
                data_pubblicazione  TEXT,
                cve_correlate       TEXT,
                cvss                REAL,
                severity            TEXT,
                tecnologia          TEXT,
                tipologia_attacco   TEXT,
                argomenti           TEXT,
                is_exploited        BOOLEAN,
                has_poc             BOOLEAN,
                data_inserimento    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_aggiornamento  TIMESTAMP
            )
        ''')
        for col, definition in [("severity", "TEXT"), ("data_aggiornamento", "TIMESTAMP")]:
            try:
                conn.execute(f"ALTER TABLE bollettini ADD COLUMN {col} {definition}")
                logging.info(f"Colonna '{col}' aggiunta al DB esistente.")
            except sqlite3.OperationalError:
                pass


def get_date_per_url() -> dict[str, str | None]:
    """
    Ritorna {url: data_pubblicazione} per tutti i bollettini.
    """
    with sqlite3.connect(DB_PATH) as conn:
        return {
            row[0]: row[1]
            for row in conn.execute("SELECT url, data_pubblicazione FROM bollettini").fetchall()
        }


def salva_bollettini(bollettini: list[Bollettino]) -> int:
    """
    Inserisce i nuovi bollettini.
    """
    if not bollettini:
        return 0
    with sqlite3.connect(DB_PATH) as conn:
        prima = conn.total_changes
        conn.executemany(
            '''INSERT OR IGNORE INTO bollettini
                (titolo, url, data_pubblicazione, cve_correlate, cvss, severity,
                 tecnologia, tipologia_attacco, argomenti, is_exploited, has_poc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            [
                (b.titolo, b.url, b.data_pubblicazione,
                 json.dumps(b.cve_correlate), b.cvss, b.severity,
                 b.tecnologia, b.tipologia_attacco,
                 json.dumps(b.argomenti), b.is_exploited, b.has_poc)
                for b in bollettini
            ],
        )
        return conn.total_changes - prima


def aggiorna_bollettini(bollettini: list[Bollettino]) -> int:
    """Aggiorna i bollettini modificati"""
    if not bollettini:
        return 0
    with sqlite3.connect(DB_PATH) as conn:
        for b in bollettini:
            conn.execute('''
                UPDATE bollettini SET
                    titolo             = ?,
                    data_pubblicazione = ?,
                    cvss               = ?,
                    severity           = ?,
                    cve_correlate      = ?,
                    tecnologia         = ?,
                    tipologia_attacco  = ?,
                    argomenti          = ?,
                    is_exploited       = ?,
                    has_poc            = ?,
                    data_aggiornamento = CURRENT_TIMESTAMP
                WHERE url = ?
            ''', (
                b.titolo, b.data_pubblicazione, b.cvss, b.severity,
                json.dumps(b.cve_correlate), b.tecnologia, b.tipologia_attacco,
                json.dumps(b.argomenti), b.is_exploited, b.has_poc, b.url,
            ))
            logging.info(f"Bollettino aggiornato: {b.url}")
    return len(bollettini)


def get_bollettini_senza_cvss() -> list[tuple]:
    """Ritorna (id, cve_correlate) per i bollettini con CVSS NULL o 0."""
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT id, cve_correlate FROM bollettini WHERE cvss IS NULL OR cvss = 0"
        ).fetchall()


def aggiorna_cvss_batch(aggiornamenti: list[tuple[int, float, str]]) -> None:
    """Aggiorna CVSS e severity"""
    if not aggiornamenti:
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            "UPDATE bollettini SET cvss=?, severity=?, data_aggiornamento=CURRENT_TIMESTAMP WHERE id=?",
            [(cvss, severity, bid) for bid, cvss, severity in aggiornamenti],
        )