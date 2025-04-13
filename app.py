from flask import Flask, render_template, request, jsonify
import requests
import socket

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    try:
        if not url.startswith("http"):
            url = "https://" + url

        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(domain)

        ip_info = requests.get(f"https://ipinfo.io/{ip}/json").json()

        abuse_headers = {
            'Key': "24795fe4505453d1f5ecd2ffb12129cee6e32378ca793197f487050affa99843ee49cc0efb333c59",
            'Accept': 'application/json'
        }
        abuse_params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        abuse_data = requests.get("https://api.abuseipdb.com/api/v2/check", headers=abuse_headers, params=abuse_params).json()

        vt_headers = {
            "x-apikey": "e54cae57a1f8194aa024edd58e7e575b8940b1be83908219073218cecc8c33b4"
        }
        vt_data = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=vt_headers).json()
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        return jsonify({
            "ip": ip,
            "city": ip_info.get("city", "Unknown"),
            "country": ip_info.get("country", "Unknown"),
            "org": ip_info.get("org", "Unknown"),
            "abuse_score": abuse_data.get("data", {}).get("abuseConfidenceScore", "N/A"),
            "reports": abuse_data.get("data", {}).get("totalReports", "N/A"),
            "malicious": stats.get("malicious", "N/A"),
            "suspicious": stats.get("suspicious", "N/A"),
        })

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)