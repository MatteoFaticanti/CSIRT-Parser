import sqlite3
import json
import logging
from models import Bollettino
from typing import List, Set

DB_PATH = "csirt_data.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute('''
            CREATE TABLE IF NOT EXISTS bollettini (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titolo TEXT NOT NULL,
                url TEXT UNIQUE NOT NULL,
                data_pubblicazione TEXT,
                cve_correlate TEXT, 
                cvss REAL,
                tecnologia TEXT,
                tipologia_attacco TEXT,
                argomenti TEXT
                is_exploited BOOLEAN,
                has_poc BOOLEAN,
                data_inserimento TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

def get_url_noti() -> Set[str]:
    """Recupera tutti gli URL già processati per il delta load."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM bollettini")
        return {row[0] for row in cursor.fetchall()}

def salva_bollettini(bollettini: List[Bollettino]) -> int:
    """Salva una lista di modelli Bollettino nel database."""
    inseriti = 0
    with sqlite3.connect(DB_PATH) as conn:
        for b in bollettini:
            try:
                conn.execute('''
                    INSERT INTO bollettini (titolo, url, data_pubblicazione, cve_correlate, cvss, tecnologia, tipologia_attacco, argomenti, is_exploited, has_poc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    b.titolo, b.url, b.data_pubblicazione, 
                    json.dumps(b.cve_correlate), b.cvss, b.tecnologia, b.tipologia_attacco,
                    json.dumps(b.argomenti), b.is_exploited, b.has_poc
                ))
                inseriti += 1
            except sqlite3.IntegrityError:
                pass # Duplicato ignorato
    return inseriti
