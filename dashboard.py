from flask import Flask
from storage import get_all_alerts

app = Flask(__name__)

@app.route("/")
def home():
    alerts = get_all_alerts()

    rows_html = ""
    for alert in alerts:
        rows_html += f"<tr><td>{alert[0]}</td><td>{alert[1]}</td><td>{alert[2]}</td><td>{alert[3]}</td><td>{alert[4]}</td><td>{alert[5]}</td></tr>"
    return f"""
    <html>
    <head>
        <meta http-equiv="refresh" content="5">
        <title>Intrusion Alerts</title>
    </head>
    <body>
        <h1>Intrusion Alerts</h1>
        <table border="1">
            <tr><th>Attack ID</th><th>IP(s)</th><th>Type</th><th>Count</th><th>First Seen</th><th>Last Seen</th></tr>
            {rows_html}
        </table>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)