from flask import Flask
from storage import get_all_alerts

app = Flask(__name__)

@app.route("/")
def home():
    alerts = get_all_alerts()

    rows_html = ""
    for alert in alerts:
        rows_html += f"<tr><td>{alert[1]}</td><td>{alert[2]}</td><td>{alert[3]}</td></tr>"
    return f"""
    <h1>Intrusion Alerts</h1>
    <table border = "1">
        <tr><th>IP</th><th>Type</th><th>Count</th></tr>
        {rows_html}
    </table>
    """

if __name__ == "__main__":
    app.run(debug=True)