import sqlite3
import json
import os
from datetime import datetime

class ShadowFoxDB:
    def __init__(self, db_path='data/shadowfox.db'):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        c = self.conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS recon (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mission_id TEXT,
            timestamp TEXT,
            data TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS mutations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mission_id TEXT,
            timestamp TEXT,
            payload TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS jwt_attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mission_id TEXT,
            timestamp TEXT,
            result TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS ai_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mission_id TEXT,
            timestamp TEXT,
            decision TEXT
        )""")
        self.conn.commit()

    def log_recon_result(self, mission_id, data):
        self._insert('recon', mission_id, data)

    def log_mutation(self, mission_id, payload):
        self._insert('mutations', mission_id, payload)

    def log_jwt_attack(self, mission_id, result):
        self._insert('jwt_attacks', mission_id, result)

    def log_ai_decision(self, mission_id, decision):
        self._insert('ai_decisions', mission_id, decision)

    def _insert(self, table, mission_id, content):
        c = self.conn.cursor()
        c.execute(f"INSERT INTO {table} (mission_id, timestamp, { 'data' if table == 'recon' else 'result' if table == 'jwt_attacks' else 'decision' if table == 'ai_decisions' else 'payload' }) VALUES (?, ?, ?)",
                  (mission_id, datetime.now().isoformat(), json.dumps(content)))
        self.conn.commit()

    def get_mission_history(self, table='recon'):
        c = self.conn.cursor()
        c.execute(f"SELECT * FROM {table} ORDER BY timestamp DESC LIMIT 10")
        return c.fetchall()
