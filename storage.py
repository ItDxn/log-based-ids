import sqlite3

DB_PATH = "alerts.db"

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT NOT NULL,"
        "alert_type TEXT NOT NULL,"
        "count INTEGER NOT NULL,"
        "first_seen TEXT NOT NULL,"
        "last_seen TEXT NOT NULL)")
    conn.commit()
    conn.close()


#Saving Alert
def save_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts (ip, alert_type, count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
    (alert['ip'], alert['type'], alert['count'], str(alert['first_seen']), str(alert['last_seen'])))
    conn.commit()
    conn.close()

#Retrieving all Alerts
def get_all_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts")
    rows = cursor.fetchall()
    conn.close()
    return rows

#Retrieving Alerts by IP
def get_alerts_ip(ip):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE ip = ?", (ip,))
    rows = cursor.fetchall()
    conn.close()
    return rows