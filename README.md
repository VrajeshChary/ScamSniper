# 🛡️ Scam Sniper — AI-Powered Online Scam & Fraud Detector

Scam Sniper is an intelligent anti-fraud platform that scans suspicious URLs, analyzes potential scam content, and empowers users with real-time verdicts using threat intelligence APIs. Built for scalability and speed, it helps fight phishing, scams, and fraud — before damage is done.

![Scam Sniper Banner](https://via.placeholder.com/800x250?text=Scam+Sniper+%7C+AI+Anti-Fraud+Tool)

## 🎯 Features

- 🔍 **Real-Time URL Scan** — Analyzes any suspicious link using VirusTotal, AbuseIPDB, WHOIS, Google Safe Browsing, and more
- 📷 **Live Website Screenshot** — Visualize the scanned website (fallback supported)
- 📊 **Layman Verdict + Detailed Report** — Easy to understand + full technical analysis
- 📂 **Scan History** — Auto-stored and scrollable
- 🧾 **Export PDF Reports** — Download full scan results
- 🔦 **Email Scam Detector** — Analyze suspicious email content for fraud patterns
- 🌐 **Dark Web Leak Checker** — Checks if your email was involved in a data breach
- 🎤 **Voice Scam Detector (Coming Soon)** — Audio phishing protection
- 🎛 **Dark Mode + Audio FX + Live Clock**
- 🎮 **Glitch Text, Typewriter, Micro-interactions**
- 🧠 **ML-Ready Architecture** — Built for NLP/AI model integration

## 🧪 How It Works

1. **Paste a link** (e.g. from a suspicious SMS/email)
2. Scam Sniper uses:
   - 📡 **IPInfo** to fetch network data
   - 🔐 **AbuseIPDB** for abuse reports
   - 🧬 **VirusTotal** for malware/suspicious flags
   - 🔎 **WHOIS** for domain age & registrar
   - 🔥 **Google Safe Browsing** for phishing detection
3. ⏱️ Within seconds, you get a full **safety verdict + technical breakdown**
4. 💾 Export your scan as a PDF and review previous scans in **History**

## 🧰 Tech Stack

| Frontend      | Backend        | APIs & Tools                                                                     |
| ------------- | -------------- | -------------------------------------------------------------------------------- |
| HTML, CSS, JS | Flask (Python) | VirusTotal, AbuseIPDB, IPInfo, WHOISXML, ScreenshotAPI.net, Google Safe Browsing |
| Animations    | REST           | html2pdf, Audio API                                                              |
| LocalStorage  | PDF Export     | Live Clock, Screenshot capture                                                   |

## 🚀 Setup & Run Locally

```bash
# Clone the repository
git clone https://github.com/yourusername/scam-sniper.git
cd scam-sniper

# Install dependencies
pip install -r requirements.txt

# Set your API keys in flask_app.py
# (VirusTotal, IPInfo, AbuseIPDB, ScreenshotAPI, WHOISXML, Google Safe Browsing)

# Run the Flask server
python flask_app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## 🧠 Future Enhancements (from Pitch Deck)

- 🧬 ML/NLP based scam prediction engine
- 🔔 Chrome Extension + Browser Plugin
- 🛡️ ScamSniper Public API
- 📥 Instant scan alerts on email/SMS
- 💼 Integration for banks, fintech, cybersecurity

## 🧑‍💻 Made For

> ⚡ **Hacksmiths United** — CR Rao AIMSCS Tech Fest  
> 🏆 Real-time cybersecurity demo & AI tool

## 🫡 Team

| Name            | Role                       |
| --------------- | -------------------------- |
| M Vrajesh Chary | Full Stack Dev / Team Lead |
| [Optional]      | API Integrator             |
| [Optional]      | UI/UX Designer             |
| [Optional]      | ML Engineer (Future Work)  |

## 📄 License

MIT License — use freely with credits.

## Deploying to PythonAnywhere

1. Sign up for a [PythonAnywhere account](https://www.pythonanywhere.com/)

2. Upload your files to PythonAnywhere using their Files tab or via Git

3. Open a Bash console in PythonAnywhere and create a virtual environment:

   ```
   mkvirtualenv --python=/usr/bin/python3.9 scam-sniper-env
   ```

4. Install the requirements:

   ```
   pip install -r requirements.txt
   ```

5. Configure a new web app:

   - Go to the Web tab and click "Add a new web app"
   - Select "Manual configuration" (not "Flask")
   - Select Python 3.9

6. Configure the WSGI file:

   - In the Web tab, click on the WSGI configuration file link
   - Replace the content with the content of your wsgi.py file
   - Update the `project_home` path to match your PythonAnywhere username and project directory

7. Set the source code and working directory:

   - In the Web tab, under "Code" section, set the "Source code" and "Working directory" to your project's directory

8. Set static files mapping:

   - In the Web tab, under "Static files", add:
     - URL: /static/
     - Directory: /home/yourusername/scam-sniper/static

9. Reload your web app and visit your site at yourusername.pythonanywhere.com

## Important Notes

- Update the project paths in wsgi.py to match your PythonAnywhere username
- Ensure all API keys in flask_app.py are still valid
- Make sure you have the static and templates folders properly set up
- Consider securing your API keys by using environment variables for production
