import os
import sys
sys.path.insert(0, 'services/api')

from dotenv import load_dotenv
load_dotenv()

import psycopg2


def create_incidents_table():
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "nokia_ssh"),
        user=os.getenv("POSTGRES_USER", "nokia"),
        password=os.getenv("POSTGRES_PASSWORD", "nokia123")
    )
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            command TEXT NOT NULL,
            severity TEXT NOT NULL,
            username TEXT,
            session_id TEXT,
            detected_at TIMESTAMP DEFAULT NOW(),
            anomaly_score REAL,
            is_anomaly BOOLEAN DEFAULT FALSE,
            action_taken TEXT,
            email_sent BOOLEAN DEFAULT FALSE,
            notes TEXT
        )
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("Incidents table created successfully!")
    print("Columns: id, command, severity, username, session_id,")
    print("         detected_at, anomaly_score, is_anomaly,")
    print("         action_taken, email_sent, notes")


if __name__ == "__main__":
    create_incidents_table()
