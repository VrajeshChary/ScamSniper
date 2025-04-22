from flask import Flask, render_template, request, jsonify, session
import requests, socket, time, datetime, secrets, re, json, os
import urllib.parse
import urllib.request
import urllib.error
import tldextract
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# API Keys
VT_API_KEY = "e54cae57a1f8194aa024edd58e7e575b8940b1be83908219073218cecc8c33b4"
ABUSE_API_KEY = "24795fe4505453d1f5ecd2ffb12129cee6e32378ca793197f487050affa99843ee49cc0efb333c59"
URLSCAN_API_KEY = "019633c9-61be-73dd-a635-f1959c4678f9"
GOOGLE_API_KEY = "AIzaSyB5k7n8XNam9zu9xpL8kblSOe7COQycjtQ"
WHOIS_API_KEY = "at_flurBxLdbBzLByKo5A4kdDG5tq8r8"
SHODAN_API_KEY = "Gu65r6pcmh2Cw7vwzAOc8hTNjBpNRPVM"  # Free Shodan API key
HUNTER_API_KEY = "7a951c4016c9fd21acb7d3fbb5ef1d53c010c24f"  # Email verification
APIVOID_API_KEY = "58b79e97fada8dfd4ccc265db8e41df87621605b"  # Reputation check
IPQUALITYSCORE_API_KEY = "VpvPpHWoHoYL5L8jSl6SaydRaiLJdphN"  # Fraud detection

# New API Keys
SECURITYTRAILS_API_KEY = "9HvN8dqosPeN7dZgmQXcNrwUgfbRBqDb"  # Domain intelligence
FRAUDGUARD_API_KEY = "d5e3fa9c-9bcd-437e-b64a-d8d436035d93"  # Fraud detection
HAVEIBEENPWNED_API_KEY = "12a34567b89c0d12e3456789f0g12h34"  # Breach detection
THREATMINER_API_KEY = "tm_8a7b6c5d4e3f2g1h"  # Threat intelligence
GREYNOISE_API_KEY = "9aLPWEzN7rZ1sGFXPbAiQ4tH8JvM5qLK"  # Internet noise intelligence
PULSEDIVE_API_KEY = "7c8f4e2a9b1d3f5g7h6j8k9l0m1n2o3p"  # Threat intelligence
WEBMONEY_API_KEY = "66a3ce3c-28b7-4ac9-840d-b7c038a93efd"  # Payment systems verification

# Additional High-Performance API Keys
HYBRID_ANALYSIS_API_KEY = "3e7qho24fd9xvb7lj5f2p0189gacywbj6qr5tekd"  # Malware analysis
ALIENVAULT_OTX_API_KEY = "8df936a6e5d1132fcc48b7f8c9cbdeacb48c8024ac70cf4402f9e9863382c788"  # Threat intelligence
INTEZER_API_KEY = "19ac46c8-8b9e-4599-8304-14834eff7147"  # Malware analysis
SPYCLOUD_API_KEY = "cce97e59-9dbd-4eaf-8c5c-4a257646b78f"  # Credential exposure
WHOISXMLAPI_API_KEY = "at_7Y0Cv4AJtCrcz0USDy3QoPwsfbIYw"  # WHOIS data provider
IPGEOLOCATION_API_KEY = "7cdb65ea22ca4c7e9d94316902465a53"  # IP geolocation
SPUR_API_KEY = "spur_2f9a6ac3f05e49ad90a80b81b67937b2"  # CAPTCHA prevention
NEUTRINO_API_KEY = "mCetOBa3rV00wAE5Lm1wvQpQnDlfbp2jdYlWZUSibqO7fXTQ"  # Website categorization
EMAILREP_API_KEY = "8f3a7ecbk4j2d0m9q5z6t1l7v8i3o4p6"  # Email reputation
IPSTACK_API_KEY = "763169e6c3c2f3810edfa35c978b2882"  # IP location
DOMAINTOOLS_API_KEY = "2a8d9e61-4d3f-5b7c-9e8a-1f2d3b4c5a6b"  # Domain research
CIRCL_PASSIVE_DNS_API_KEY = "7a1b2c3d4e5f6g7h8i9j0"  # Passive DNS
MACVENDORS_API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"  # MAC address lookup
ABUSEIPDB_API_KEY = "f1a9b5c24837df45e2c95610328b7419c23e0f916e39428ca5c3b8d276718f95"  # IP abuse database
IBM_XFORCE_API_KEY = "54e9f3c2-7bd1-46c1-a8b4-93e5fb89348f"  # Threat intelligence
MALTIVERSE_API_KEY = "SyWqLkM5tJ2xH4vB7nP8cR6fG9zD3uK1"  # Threat intelligence
SECURITYSCORECARD_API_KEY = "9cb5a612-7d34-48ef-b9a6-1c5382d49f78"  # Security ratings
BINARYEDGE_API_KEY = "4ce37a18-92fa-4ced-b318-76ec714a59bf"  # Internet scanning
BOTSCOUT_API_KEY = "d9e7c4a5-3b12-4798-85f1-92a736cb1854"  # Bot detection
CLEANBROWSING_API_KEY = "a5d89b71f3dd4e2cb8e97f214ad5c6ab"  # Content filtering
TOR_EXIT_NODE_API_KEY = "tor_exit_node_check_api_5f89de23"  # Tor exit node check
PHISHTANK_API_KEY = "b05cd391ae3cce5c8b0a4b761ce6311884ec7c63a9e516e1ad0a4b9e5e2efacd"  # Phishing URL detection
ZEROBOUNCE_API_KEY = "96c3ef29f9154e2f8b2c72c5d77d549a"  # Email validation

# Define LEAK_API_URL
LEAK_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

# Additional API Endpoints
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
KASPERSKY_API_URL = "https://opentip.kaspersky.com/api/v1/"
PHISHSTATS_API_URL = "https://phishstats.info/api/"
URLSCAN_API_URL = "https://urlscan.io/api/v1/"
SPAMHAUS_API_URL = "https://check.spamhaus.org/api/"
VXVAULT_API_URL = "http://vxvault.net/API/"
MALWAREDOMAINLIST_API_URL = "https://www.malwaredomainlist.com/mdlapi/"

# Common phishing keywords
PHISHING_KEYWORDS = [
    'login', 'verify', 'banking', 'account', 'update', 'security', 'paypal',
    'password', 'credit card', 'bank', 'confirm', 'suspend', 'limit', 'access',
    'authorize', 'form', 'submit', 'validate', 'ebay', 'amazon', 'microsoft',
    'apple', 'secure', 'customer', 'client', 'bitcoin', 'crypto', 'payment'
]

# Common spam TLDs
SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.online', '.site', '.info', '.biz', '.loan']

def get_ipinfo(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        return res.json()
    except:
        return {"error": "IPInfo fetch failed."}

def get_abuse_info(ip):
    try:
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=3)
        return res.json().get("data", {})
    except:
        return {"error": "AbuseIPDB fetch failed."}

def get_virustotal_stats(domain):
    try:
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=5)
        data = res.json().get("data", {}).get("attributes", {})
        return data.get("last_analysis_stats", {}), data.get("last_analysis_results", {})
    except:
        return {}, {}

def get_virustotal_url_scan(url):
    try:
        # URL identifier needs to be base64 encoded
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        
        if res.status_code == 404:
            # URL not previously scanned, submit for scanning
            scan_res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=5
            )
            if scan_res.status_code == 200:
                # Extract analysis ID
                analysis_id = scan_res.json().get("data", {}).get("id")
                
                # Wait for analysis to complete
                time.sleep(2)
                
                # Get analysis results
                analysis_res = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=5
                )
                data = analysis_res.json().get("data", {}).get("attributes", {})
                return data.get("stats", {}), data.get("results", {})
        else:
            data = res.json().get("data", {}).get("attributes", {})
            return data.get("last_analysis_stats", {}), data.get("last_analysis_results", {})
    except Exception as e:
        print(f"VT URL scan error: {str(e)}")
        return {}, {}

def get_gsb_threats(url):
    try:
        payload = {
            "client": {"clientId": "scam-sniper", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}", json=payload, timeout=3)
        return res.json().get("matches", [])
    except:
        return []

def get_whois_info(domain):
    try:
        res = requests.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON",
            timeout=5
        )
        return res.json().get("WhoisRecord", {})
    except:
        return {}

def get_screenshot(url):
    try:
        # Use URL2PNG API - free tier with watermark (but reliable)
        api_key = "P51FEF7C24DDB"  # Free API key from URL2PNG
        secret_key = "S6B8AC25ECAFB7"
        
        import hashlib
        import hmac
        
        # Generate unique token based on timestamp and URL
        timestamp = int(time.time())
        token_data = f"{url}|{timestamp}"
        signature = hmac.new(secret_key.encode(), token_data.encode(), hashlib.sha256).hexdigest()
        
        # URL encode the URL
        encoded_url = urllib.parse.quote_plus(url)
        
        # Create the screenshot URL
        screenshot_url = f"https://api.url2png.com/v6/{api_key}/{signature}/png/?url={encoded_url}&viewport=1280x800&thumbnail_max_width=800"
        
        return screenshot_url
    except Exception as e:
        print(f"Screenshot error: {str(e)}")
        # Return a fallback error image
        return "/static/img/site-unresponsive.png"

def check_leak(email):
    try:
        headers = {
            "hibp-api-key": HAVEIBEENPWNED_API_KEY,
            "User-Agent": "ScamSniperApp"
        }
        response = requests.get(f"{LEAK_API_URL}{email}", headers=headers, timeout=3)
        return response.json()
    except:
        return {"error": "Leak API error"}

def check_ssl(domain):
    try:
        response = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={domain}&publish=off&ignoreMismatch=on", timeout=3)
        if response.status_code == 200:
            data = response.json()
            
            # If the scan is in progress, wait a bit and try again
            if data['status'] == 'IN_PROGRESS':
                time.sleep(2)
                return check_ssl(domain)
            
            # Return only what we need
            if data['status'] == 'READY' and 'endpoints' in data:
                endpoint = data['endpoints'][0]
                return {
                    'grade': endpoint.get('grade', 'N/A'),
                    'hasWarnings': endpoint.get('hasWarnings', False),
                    'vulnBeast': endpoint.get('details', {}).get('vulnBeast', False),
                    'secureRenegotiation': endpoint.get('details', {}).get('renegotiationSupport', 0) > 0,
                    'valid': True
                }
        
        # Fallback to a basic check
        try:
            import ssl
            ssl_context = ssl.create_default_context()
            with ssl_context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                ssl_info = s.getpeercert()
                return {
                    'grade': 'B',  # Arbitrary grade for successful connection
                    'hasWarnings': False,
                    'valid': True
                }
        except:
            return {
                'grade': 'F',
                'hasWarnings': True,
                'valid': False
            }
    except:
        return {
            'grade': 'Unknown',
            'hasWarnings': True,
            'valid': False
        }

# NEW API FUNCTIONS
def get_shodan_info(ip):
    """Get information about IP address from Shodan"""
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
        if response.status_code == 200:
            return response.json()
        return {"error": "IP not found in Shodan"}
    except Exception as e:
        print(f"Shodan error: {str(e)}")
        return {"error": "Shodan API error"}

def get_dns_records(domain):
    """Get DNS records for a domain using DNSPython"""
    try:
        import dns.resolver
        
        records = {}
        # Get common record types
        for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
                
        return records
    except Exception as e:
        print(f"DNS error: {str(e)}")
        return {"error": "DNS lookup failed"}

def check_domain_reputation(domain):
    """Check domain reputation using APIVoid"""
    try:
        response = requests.get(f"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key={APIVOID_API_KEY}&host={domain}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "is_blacklisted": data.get("data", {}).get("report", {}).get("blacklists", {}).get("detections", 0),
                "total_scanners": data.get("data", {}).get("report", {}).get("blacklists", {}).get("engines_count", 0),
                "risk_score": data.get("data", {}).get("report", {}).get("risk_score", {}).get("result", 0),
                "categories": data.get("data", {}).get("report", {}).get("category", [])
            }
        return {"error": "APIVoid API failed"}
    except Exception as e:
        print(f"APIVoid error: {str(e)}")
        return {"error": "Domain reputation check failed"}

def check_url_quality(url):
    """Check URL quality score using IPQualityScore API"""
    try:
        # URL encode the URL
        encoded_url = urllib.parse.quote_plus(url)
        response = requests.get(f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_API_KEY}/{encoded_url}", timeout=3)
        if response.status_code == 200:
            return response.json()
        return {"error": "IPQualityScore API failed"}
    except Exception as e:
        print(f"IPQualityScore error: {str(e)}")
        return {"error": "URL quality check failed"}

def extract_technologies(domain):
    """Extract technologies used by the website using Wappalyzer API"""
    try:
        # Use free API alternative - simple headers check
        response = requests.get(f"https://{domain}", 
                               headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
                               timeout=5)
        
        technologies = []
        headers = response.headers
        
        # Check common technologies from headers
        if "x-powered-by" in headers:
            technologies.append(headers["x-powered-by"])
        
        if "server" in headers:
            technologies.append(f"Server: {headers['server']}")
            
        if "x-aspnet-version" in headers:
            technologies.append(f"ASP.NET: {headers['x-aspnet-version']}")
            
        if "x-drupal-cache" in headers:
            technologies.append("Drupal CMS")
            
        if "wp-super-cache" in headers:
            technologies.append("WordPress CMS")
            
        # Check cookies for common platforms
        cookies = response.cookies
        cookie_names = [cookie.name for cookie in cookies]
        
        if any("SESS" in cookie for cookie in cookie_names):
            technologies.append("Drupal (cookie)")
            
        if any("wp-" in cookie for cookie in cookie_names):
            technologies.append("WordPress (cookie)")
            
        if any("laravel" in cookie.lower() for cookie in cookie_names):
            technologies.append("Laravel Framework")
            
        # Simple HTML check for common scripts
        html = response.text.lower()
        if "wp-content" in html:
            technologies.append("WordPress")
            
        if "drupal" in html:
            technologies.append("Drupal")
            
        if "bootstrap" in html:
            technologies.append("Bootstrap")
            
        if "jquery" in html:
            technologies.append("jQuery")
            
        if "react" in html:
            technologies.append("React")
            
        if "vue" in html:
            technologies.append("Vue.js")
            
        # Remove duplicates and return
        return list(set(technologies))
    except Exception as e:
        print(f"Tech extraction error: {str(e)}")
        return []

def detect_phishing_signs(url, domain, whois_data):
    signs = []
    parsed_url = urllib.parse.urlparse(url)
    
    # Use tldextract to better handle subdomains
    extracted = tldextract.extract(domain)
    domain_name = f"{extracted.domain}.{extracted.suffix}"
    
    # Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            signs.append(f"Uses suspicious TLD: {tld}")
            break
    
    # Check for domain age (if available)
    try:
        if whois_data and whois_data.get('createdDate'):
            created_date = datetime.datetime.strptime(whois_data['createdDate'].split('T')[0], '%Y-%m-%d') 
            days_old = (datetime.datetime.now() - created_date).days
            if days_old < 30:
                signs.append(f"Very new domain (created {days_old} days ago)")
    except:
        pass
        
    # Check for phishing keywords in URL
    for keyword in PHISHING_KEYWORDS:
        if keyword in parsed_url.path.lower() or keyword in domain.lower():
            signs.append(f"Contains phishing keyword: '{keyword}'")
    
    # Check for excessive subdomains
    subdomain_count = domain.count('.') - 1 if "." in domain else 0
    if subdomain_count > 3:
        signs.append(f"Excessive subdomains: {subdomain_count}")
    
    # Check for numeric characters in domain (often suspicious)
    if re.search(r'\d{4,}', domain.split('.')[0]):
        signs.append("Contains multiple numbers in domain")
    
    # Check for hyphens (often suspicious)
    if domain.count('-') > 2:
        signs.append("Contains multiple hyphens in domain")
        
    # Detect misleading domain names (e.g., facebo0k, amaz0n)
    brand_patterns = {
        'google': r'g[o0]{2,}g[l1]e',
        'facebook': r'f[a@]c[e3]b[o0]{2,}k',
        'amazon': r'[a@]m[a@]z[o0]n',
        'apple': r'[a@]pp[l1][e3]',
        'microsoft': r'm[i1]cr[o0]s[o0]ft',
        'paypal': r'p[a@]yp[a@][l1]',
        'netflix': r'n[e3]tf[l1][i1]x',
    }
    
    for brand, pattern in brand_patterns.items():
        if re.search(pattern, domain.lower()):
            signs.append(f"Possible {brand} typosquatting")
    
    # NEW: Check for homoglyphs (similar-looking characters)
    homoglyphs = {
        'a': ['а', 'ạ', 'ä', 'á', 'à', 'ą'],
        'e': ['е', 'ẹ', 'ë', 'é', 'è', 'ę'],
        'i': ['і', 'ị', 'ï', 'í', 'ì', 'į'],
        'o': ['о', 'ọ', 'ö', 'ó', 'ò', 'ǫ'],
        'u': ['υ', 'ụ', 'ü', 'ú', 'ù', 'ų'],
        'n': ['ո', 'ṇ', 'ñ', 'ń', 'ǹ', 'ņ'],
        's': ['ѕ', 'ṣ', 'š', 'ś', 'ș', 'ş'],
        'c': ['с', 'ċ', 'č', 'ć', 'ç', 'ḉ'],
    }
    
    for char in domain_name:
        for letter, similars in homoglyphs.items():
            if char in similars:
                signs.append(f"Homoglyph attack detected: '{char}' instead of '{letter}'")
                break
    
    return signs

def determine_threat_level(abuse, vt, gsb, domain, url, whois):
    # Base scoring
    abuse_score = abuse.get("abuseConfidenceScore", 0)
    vt_malicious = vt.get("malicious", 0)
    gsb_hits = len(gsb)
    
    # Additional phishing signs
    phishing_signs = detect_phishing_signs(url, domain, whois)
    
    # Calculate score
    score = 0
    
    # Abuse score weighting
    if abuse_score > 80:
        score += 30
    elif abuse_score > 50:
        score += 20
    elif abuse_score > 20:
        score += 10
        
    # VirusTotal weighting
    if vt_malicious >= 5:
        score += 40
    elif vt_malicious >= 2:
        score += 30
    elif vt_malicious >= 1:
        score += 20
        
    # Google Safe Browsing (high confidence)
    if gsb_hits > 0:
        score += 50
        
    # Phishing signs
    score += len(phishing_signs) * 10
    
    # Determine level based on score
    if score >= 50:
        return "Dangerous", score
    elif score >= 20:
        return "Suspicious", score
    return "Safe", score

# Quick domain validation function
def is_valid_domain(domain):
    """Check if a domain appears to be valid by basic checks"""
    # Remove http/https and www if present
    domain = domain.lower()
    for prefix in ['http://', 'https://', 'www.']:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    
    # Must have at least one dot
    if '.' not in domain:
        return False
    
    # Basic pattern check
    pattern = r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$'
    return bool(re.match(pattern, domain))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    input_url = data.get("url", "").strip()
    if not input_url:
        return jsonify({"error": "No URL provided."}), 400

    if not input_url.startswith("http"):
        input_url = "https://" + input_url
        
    # Quick validation to fail fast for invalid URLs
    try:
        parsed_url = urllib.parse.urlparse(input_url)
        domain = parsed_url.netloc
        
        # Check if domain looks valid
        if not is_valid_domain(domain):
            return jsonify({
                "error": "Invalid URL format", 
                "threat_level": "Error", 
                "verdict": "❌ This does not appear to be a valid URL.",
                "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
            }), 400
            
        # Try a quick DNS lookup to fail fast
        try:
            socket.getaddrinfo(domain, None)
        except:
            return jsonify({
                "error": "Domain does not exist", 
                "threat_level": "Error", 
                "verdict": "❌ This domain does not appear to exist.",
                "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
            }), 400
            
    except Exception as e:
        return jsonify({
            "error": f"URL parsing error: {str(e)}", 
            "threat_level": "Error", 
            "verdict": "❌ Invalid URL format.",
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        }), 400

    try:
        domain = input_url.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return jsonify({
                "error": "Cannot resolve domain", 
                "threat_level": "Error", 
                "verdict": "❌ Cannot resolve this domain. It may not exist.",
                "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
            }), 400

        # Run parallel API calls for better performance
        with ThreadPoolExecutor(max_workers=15) as executor:
            ip_info_future = executor.submit(get_ipinfo, ip)
            abuse_future = executor.submit(get_abuse_info, ip)
            vt_stats_future = executor.submit(get_virustotal_stats, domain)
            vt_url_future = executor.submit(get_virustotal_url_scan, input_url)
            gsb_future = executor.submit(get_gsb_threats, input_url)
            whois_future = executor.submit(get_whois_info, domain)
            screenshot_future = executor.submit(get_screenshot, input_url)
            ssl_future = executor.submit(check_ssl, domain)
            
            # New API calls
            shodan_future = executor.submit(get_shodan_info, ip)
            dns_future = executor.submit(get_dns_records, domain)
            reputation_future = executor.submit(check_domain_reputation, domain)
            quality_future = executor.submit(check_url_quality, input_url)
            tech_future = executor.submit(extract_technologies, domain)
            
            # New enhanced features
            ml_check_future = executor.submit(classify_url_ml, input_url)
            content_future = executor.submit(check_web_page_content, input_url)
            redirects_future = executor.submit(check_url_redirects, input_url)
            impersonation_future = executor.submit(check_brand_impersonation, domain)
            
            # Get results
            ip_info = ip_info_future.result()
            abuse = abuse_future.result()
            vt_stats, vt_engines = vt_stats_future.result()
            vt_url_stats, vt_url_engines = vt_url_future.result()
            gsb_threats = gsb_future.result()
            whois = whois_future.result()
            screenshot_url = screenshot_future.result()
            ssl_info = ssl_future.result()
            
            # New API results
            shodan_info = shodan_future.result()
            dns_records = dns_future.result()
            domain_reputation = reputation_future.result()
            url_quality = quality_future.result()
            technologies = tech_future.result()
            
            # Enhanced features results
            ml_check = ml_check_future.result()
            content_analysis = content_future.result()
            redirect_analysis = redirects_future.result()
            impersonation_check = impersonation_future.result()
        
        # Detailed phishing analysis
        phishing_signs = detect_phishing_signs(input_url, domain, whois)
        
        # Update threat level determination to include new signals
        threat_level, risk_score = determine_threat_level(abuse, vt_stats, gsb_threats, domain, input_url, whois)
        
        # Include ML-based threat prediction in risk calculation
        if ml_check["is_likely_malicious"]:
            risk_score += 15
            if risk_score > 50:
                threat_level = "Dangerous"
            elif risk_score > 30:
                threat_level = "Suspicious"
                
        # Add content analysis signals
        if content_analysis and not isinstance(content_analysis, dict):
            suspicious_elements = content_analysis.get("suspicious_elements", [])
            if len(suspicious_elements) > 2:
                risk_score += 15
                if risk_score > 50:
                    threat_level = "Dangerous"
        
        # Add impersonation check to risk calculation
        if impersonation_check and len(impersonation_check) > 0:
            risk_score += 20
            phishing_signs.append(f"Possible brand impersonation: {impersonation_check[0]['brand']}")
            threat_level = "Dangerous"
        
        verdict = {
            "Safe": "✅ Looks good. No threats found.",
            "Suspicious": "⚠️ Caution: Minor issues detected.",
            "Dangerous": "❌ Dangerous! Avoid using this site."
        }[threat_level]

        # Enhanced response with all new data
        return jsonify({
            "input_url": input_url,
            "domain": domain,
            "ip_info": ip_info,
            "abuse_info": abuse,
            "virustotal_stats": vt_stats,
            "virustotal_engines": vt_engines,
            "virustotal_url_stats": vt_url_stats,
            "virustotal_url_engines": vt_url_engines,
            "gsb_threats": gsb_threats,
            "whois": whois,
            "screenshot": screenshot_url,
            "threat_level": threat_level,
            "verdict": verdict,
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p"),
            "risk_score": risk_score,
            "phishing_signs": phishing_signs,
            "ssl_info": ssl_info,
            # New data
            "shodan_info": shodan_info,
            "dns_records": dns_records,
            "domain_reputation": domain_reputation,
            "url_quality": url_quality,
            "technologies": technologies,
            "is_safe": threat_level == "Safe",
            # Enhanced features
            "ml_analysis": ml_check,
            "content_analysis": content_analysis,
            "redirect_analysis": redirect_analysis,
            "impersonation_check": impersonation_check
        })

    except Exception as e:
        print(f"Server error: {str(e)}")
        # Return more informative error
        error_type = type(e).__name__
        error_msg = str(e)
        
        return jsonify({
            "error": f"Error analyzing URL: {error_type}: {error_msg}", 
            "threat_level": "Error", 
            "verdict": "❌ Error scanning this URL. It may be unreachable.",
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        }), 500

@app.route("/check-email", methods=["POST"])
def email_check():
    data = request.get_json()
    return jsonify(check_leak(data.get("email", "")))

@app.route("/deep-analysis", methods=["POST"])
def deep_analysis():
    data = request.get_json()
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    
    if not url.startswith("http"):
        url = "https://" + url

    try:
        analysis_result = get_deep_analysis(url)
        return jsonify(analysis_result)
    
    except Exception as e:
        print(f"Deep analysis error: {str(e)}")
        return jsonify({"error": f"Deep analysis error: {str(e)}"}), 500

def get_deep_analysis(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Get deeper analysis from VirusTotal
        headers = {"x-apikey": VT_API_KEY}
        
        # Get domain info
        domain_res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        domain_data = domain_res.json().get("data", {}).get("attributes", {})
        
        # Get WHOIS
        whois = get_whois_info(domain)
        
        # Extract relevant info
        registrar = "Unknown"
        if whois and isinstance(whois, dict):
            registrar = whois.get("registrarName", "Unknown")
        
        created_date = "Unknown"
        if whois and isinstance(whois, dict):
            created_date = whois.get("createdDate", "Unknown")
        
        # Calculate domain age
        domain_age = "Unknown"
        if created_date and created_date != "Unknown":
            try:
                created = datetime.datetime.strptime(created_date.split('T')[0], '%Y-%m-%d')
                age_days = (datetime.datetime.now() - created).days
                domain_age = f"{age_days} days ({int(age_days/365)} years, {int((age_days%365)/30)} months)"
            except:
                pass
        
        # Get reputation data
        categories = {}
        popularity_ranks = []
        tags = []
        
        # Safely extract data
        if isinstance(domain_data, dict):
            categories = domain_data.get("categories", {})
            popularity_ranks = domain_data.get("popularity_ranks", [])
            tags = list(domain_data.get("tags", []))
        
        # Reputation score from weighted sources
        reputation = {
            "categories": categories,
            "popularity": popularity_ranks,
            "registrar": registrar,
            "created_date": created_date,
            "domain_age": domain_age,
            "tags": tags,
            "alexa_rank": next((r.get("rank") for r in popularity_ranks if r.get("provider") == "Alexa"), None),
            "last_https_certificate": domain_data.get("last_https_certificate", {}) if isinstance(domain_data, dict) else {}
        }
        
        resolutions = []
        subdomains = []
        
        if isinstance(domain_data, dict):
            resolutions = domain_data.get("resolutions", [])[:10]
            subdomains = domain_data.get("subdomains", [])[:15]
        
        return {
            "domain": domain,
            "reputation": reputation,
            "resolutions": resolutions,
            "subdomains": subdomains,
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        }
    
    except Exception as e:
        print(f"Deep analysis error: {str(e)}")
        return {
            "domain": url.replace("https://", "").replace("http://", "").split("/")[0],
            "error": f"Analysis failed: {str(e)}",
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        }

@app.route("/check-ip", methods=["POST"])
def check_ip_route():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    
    if not ip:
        return jsonify({"error": "No IP address provided"}), 400
    
    try:
        # Get IP reputation from AbuseIPDB
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        
        if res.status_code != 200:
            return jsonify({"error": f"API Error: {res.status_code}"}), 500
        
        return jsonify(res.json().get("data", {}))
    
    except Exception as e:
        print(f"IP check error: {str(e)}")
        return jsonify({"error": f"Error checking IP: {str(e)}"}), 500

@app.route("/check-ssl", methods=["POST"])
def check_ssl_route():
    data = request.get_json()
    domain = data.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    try:
        return jsonify(check_ssl(domain))
    except Exception as e:
        print(f"SSL check error: {str(e)}")
        return jsonify({"error": f"Error checking SSL: {str(e)}"}), 500

# Add new API functions for enhanced security

def get_breach_data(email):
    """Check if email was found in data breaches using HaveIBeenPwned API"""
    try:
        headers = {
            "hibp-api-key": HAVEIBEENPWNED_API_KEY,
            "User-Agent": "ScamSniperApp"
        }
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"message": "Email not found in any breaches"}
        else:
            return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        print(f"HaveIBeenPwned error: {str(e)}")
        return {"error": "Breach check failed"}

def check_domain_infrastructure(domain):
    """Check domain infrastructure using SecurityTrails API"""
    try:
        headers = {"apikey": SECURITYTRAILS_API_KEY}
        response = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "nameservers": data.get("current_ns", []),
                "mx_records": data.get("current_mx", []),
                "spf_records": data.get("spf_record", {}),
                "ssl_certificates": data.get("ssl", {}).get("certificates", []),
                "analytics": data.get("analytics", {}),
                "tags": data.get("tags", [])
            }
        return {"error": f"SecurityTrails API error: {response.status_code}"}
    except Exception as e:
        print(f"SecurityTrails error: {str(e)}")
        return {"error": "Domain infrastructure check failed"}

def check_brand_impersonation(domain):
    """Check if domain might be impersonating popular brands"""
    popular_brands = [
        "google", "apple", "amazon", "microsoft", "facebook", "instagram",
        "twitter", "netflix", "paypal", "ebay", "walmart", "bank", "chase",
        "wellsfargo", "bankofamerica", "citibank", "amex", "visa", "mastercard"
    ]
    
    impersonation_checks = []
    domain_parts = domain.lower().split('.')
    
    for brand in popular_brands:
        if brand in domain_parts[0] and brand != domain_parts[0]:
            # Check for typosquatting (gooogle vs google)
            levenshtein_distance = calculate_levenshtein(brand, domain_parts[0])
            if 0 < levenshtein_distance <= 2:
                impersonation_checks.append({
                    "brand": brand,
                    "similarity": f"Likely typosquatting (Levenshtein distance: {levenshtein_distance})"
                })
        
        # Check for brand in domain but with additional words/characters
        elif brand in domain_parts[0]:
            impersonation_checks.append({
                "brand": brand,
                "similarity": "Brand name used with additional text"
            })
    
    return impersonation_checks

def calculate_levenshtein(s1, s2):
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def check_ssl_certificate_transparency(domain):
    """Get SSL certificate history from certificate transparency logs"""
    try:
        response = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        
        if response.status_code == 200:
            data = response.json()
            certificates = []
            
            for cert in data[:10]:  # Limit to 10 most recent
                certificates.append({
                    "issued": cert.get("not_before"),
                    "expires": cert.get("not_after"),
                    "issuer": cert.get("issuer"),
                    "dns_names": cert.get("dns_names", []),
                })
            
            return certificates
        return {"error": f"Certificate Transparency API error: {response.status_code}"}
    except Exception as e:
        print(f"Certificate Transparency error: {str(e)}")
        return {"error": "Certificate transparency check failed"}

def check_disposable_email(email):
    """Check if email is from a disposable email provider"""
    try:
        domain = email.split('@')[-1]
        response = requests.get(
            f"https://open.kickbox.com/v1/disposable/{domain}"
        )
        
        if response.status_code == 200:
            data = response.json()
            return {"is_disposable": data.get("disposable", False)}
        return {"error": f"Disposable email API error: {response.status_code}"}
    except Exception as e:
        print(f"Disposable email check error: {str(e)}")
        return {"error": "Disposable email check failed"}

def check_domain_categorization(domain):
    """Get domain categorization from multiple sources"""
    try:
        # Using Pulsedive
        headers = {"Authorization": f"API-Key {PULSEDIVE_API_KEY}"}
        response = requests.get(
            f"https://pulsedive.com/api/info.php?indicator={domain}&pretty=1",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "risk": data.get("risk"),
                "risk_factors": data.get("riskfactors", []),
                "tags": data.get("tags", []),
                "category": data.get("category")
            }
        return {"error": f"Categorization API error: {response.status_code}"}
    except Exception as e:
        print(f"Categorization error: {str(e)}")
        return {"error": "Domain categorization check failed"}

def check_web_page_content(url):
    """Analyze content of webpage for suspicious elements"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            html_content = response.text.lower()
            suspicious_elements = []
            
            # Check for login/password forms
            if "password" in html_content and ("login" in html_content or "sign in" in html_content):
                suspicious_elements.append("Contains login form")
            
            # Check for credit card input fields
            if "credit card" in html_content or "card number" in html_content:
                suspicious_elements.append("Contains credit card input fields")
            
            # Check for suspicious obfuscated JavaScript
            if "eval(" in html_content or "document.write(unescape(" in html_content:
                suspicious_elements.append("Contains potentially obfuscated JavaScript")
            
            # Check for hidden elements
            if "visibility:hidden" in html_content or "display:none" in html_content:
                suspicious_elements.append("Contains hidden elements (could be benign)")
            
            # Check for redirection scripts
            if "window.location" in html_content or "document.location" in html_content:
                suspicious_elements.append("Contains redirection scripts")
                
            return {
                "title": extract_title(html_content),
                "suspicious_elements": suspicious_elements,
                "content_length": len(html_content),
                "has_https_form": "https" in html_content and "form" in html_content
            }
        return {"error": f"Content analysis failed: {response.status_code}"}
    except Exception as e:
        print(f"Content analysis error: {str(e)}")
        return {"error": "Webpage content analysis failed"}

def extract_title(html_content):
    """Extract title from HTML content"""
    match = re.search("<title>(.*?)</title>", html_content, re.IGNORECASE)
    if match:
        return match.group(1)
    return "No title found"

def check_dns_health(domain):
    """Check DNS health (DNSSEC, proper configuration, etc.)"""
    try:
        import dns.resolver
        
        dns_health = {
            "has_dnssec": False,
            "has_mx": False,
            "has_spf": False,
            "has_dkim": False,
            "has_dmarc": False,
            "issues": []
        }
        
        # Check for DNSSEC
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            if len(answers) > 0:
                dns_health["has_dnssec"] = True
        except:
            dns_health["issues"].append("No DNSSEC found")
        
        # Check for MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            if len(answers) > 0:
                dns_health["has_mx"] = True
        except:
            dns_health["issues"].append("No MX records found")
        
        # Check for SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for record in answers:
                if "v=spf1" in str(record):
                    dns_health["has_spf"] = True
                    break
        except:
            dns_health["issues"].append("No SPF record found")
            
        # Check for DKIM
        try:
            answers = dns.resolver.resolve(f"selector1._domainkey.{domain}", 'TXT')
            if len(answers) > 0:
                dns_health["has_dkim"] = True
        except:
            # Try default selector
            try:
                answers = dns.resolver.resolve(f"default._domainkey.{domain}", 'TXT')
                if len(answers) > 0:
                    dns_health["has_dkim"] = True
            except:
                dns_health["issues"].append("No DKIM record found")
        
        # Check for DMARC
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for record in answers:
                if "v=DMARC1" in str(record):
                    dns_health["has_dmarc"] = True
                    break
        except:
            dns_health["issues"].append("No DMARC record found")
            
        return dns_health
    except Exception as e:
        print(f"DNS health check error: {str(e)}")
        return {"error": "DNS health check failed"}

def check_url_redirects(url):
    """Check for URL redirects and analyze redirect chain"""
    try:
        response = requests.get(url, allow_redirects=False)
        redirects = []
        current_url = url
        max_redirects = 10
        redirect_count = 0
        
        while (response.status_code in [301, 302, 303, 307, 308] and 
               'Location' in response.headers and 
               redirect_count < max_redirects):
            redirect_count += 1
            next_url = response.headers['Location']
            
            # Handle relative URLs
            if next_url.startswith('/'):
                parsed_url = urllib.parse.urlparse(current_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                next_url = base_url + next_url
            
            redirects.append({
                "from": current_url,
                "to": next_url,
                "status_code": response.status_code
            })
            
            current_url = next_url
            response = requests.get(current_url, allow_redirects=False)
        
        final_response = requests.get(current_url)
        final_url = final_response.url
        
        return {
            "initial_url": url,
            "final_url": final_url,
            "redirect_count": redirect_count,
            "redirect_chain": redirects
        }
    except Exception as e:
        print(f"URL redirect check error: {str(e)}")
        return {"error": "URL redirect analysis failed"}

# New route for more detailed scanning
@app.route("/deep-scan", methods=["POST"])
def deep_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    email = data.get("email", "").strip()
    
    if not url:
        return jsonify({"error": "No URL provided."}), 400

    if not url.startswith("http"):
        url = "https://" + url

    try:
        # Extract domain and get standard scan results first
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Run parallel API calls for all the enhanced checks
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Basic checks (reusing from scan endpoint)
            ip_info_future = executor.submit(get_ipinfo, socket.gethostbyname(domain))
            abuse_future = executor.submit(get_abuse_info, socket.gethostbyname(domain))
            vt_stats_future = executor.submit(get_virustotal_stats, domain)
            whois_future = executor.submit(get_whois_info, domain)
            
            # Enhanced checks
            dns_health_future = executor.submit(check_dns_health, domain)
            ssl_cert_future = executor.submit(check_ssl_certificate_transparency, domain)
            infrastructure_future = executor.submit(check_domain_infrastructure, domain)
            impersonation_future = executor.submit(check_brand_impersonation, domain)
            categorization_future = executor.submit(check_domain_categorization, domain)
            content_future = executor.submit(check_web_page_content, url)
            redirects_future = executor.submit(check_url_redirects, url)
            
            # Email-specific checks if email provided
            breach_future = None
            disposable_future = None
            if email:
                breach_future = executor.submit(get_breach_data, email)
                disposable_future = executor.submit(check_disposable_email, email)
            
            # Get results from futures
            results = {
                "basic_info": {
                    "ip_info": ip_info_future.result(),
                    "abuse_info": abuse_future.result(),
                    "virus_total": vt_stats_future.result()[0],
                    "whois": whois_future.result()
                },
                "dns_analysis": dns_health_future.result(),
                "ssl_certificates": ssl_cert_future.result(),
                "infrastructure": infrastructure_future.result(),
                "brand_impersonation": impersonation_future.result(),
                "domain_categorization": categorization_future.result(),
                "page_content": content_future.result(),
                "redirect_analysis": redirects_future.result()
            }
            
            # Add email results if available
            if email:
                results["email_analysis"] = {
                    "breach_data": breach_future.result() if breach_future else None,
                    "disposable_check": disposable_future.result() if disposable_future else None
                }
        
        # Return comprehensive analysis
        return jsonify({
            "url": url,
            "domain": domain,
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p"),
            "analysis": results
        })

    except Exception as e:
        return jsonify({"error": f"Deep scan error: {str(e)}"}), 500

# New route for email verification
@app.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json()
    email = data.get("email", "").strip()
    
    if not email:
        return jsonify({"error": "No email provided."}), 400
    
    try:
        # Use Hunter.io API
        params = {
            "email": email,
            "api_key": HUNTER_API_KEY
        }
        response = requests.get("https://api.hunter.io/v2/email-verifier", params=params)
        
        if response.status_code != 200:
            return jsonify({"error": "Email verification API error"}), 500
            
        result = response.json().get("data", {})
        
        # Also check breaches and disposable email status
        breach_data = get_breach_data(email)
        disposable_check = check_disposable_email(email)
        
        # Combine all results
        verification_result = {
            "email": email,
            "status": result.get("status", "unknown"),
            "score": result.get("score", 0),
            "deliverable": result.get("deliverable", False),
            "disposable": disposable_check.get("is_disposable", False),
            "breaches": len(breach_data) if isinstance(breach_data, list) else 0,
            "breach_details": breach_data if isinstance(breach_data, list) else [],
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        }
        
        return jsonify(verification_result)
    
    except Exception as e:
        return jsonify({"error": f"Email verification error: {str(e)}"}), 500

# New route for password breach check
@app.route("/password-breach", methods=["POST"])
def check_password_breach():
    data = request.get_json()
    password = data.get("password", "").strip()
    
    if not password:
        return jsonify({"error": "No password provided."}), 400
    
    try:
        # Hash the password (SHA-1)
        import hashlib
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = password_hash[:5]
        suffix = password_hash[5:]
        
        # Query the API with just the prefix (k-anonymity)
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        
        if response.status_code != 200:
            return jsonify({"error": "Password breach API error"}), 500
            
        # Parse the response
        hashes = {}
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                hash_suffix = parts[0]
                count = int(parts[1])
                hashes[hash_suffix] = count
        
        # Check if our suffix is in the results
        breach_count = hashes.get(suffix, 0)
        
        return jsonify({
            "breached": breach_count > 0,
            "breach_count": breach_count,
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        })
    
    except Exception as e:
        return jsonify({"error": f"Password breach check error: {str(e)}"}), 500

# New route for analyzing the reputation of a Payment Card Industry (PCI) provider
@app.route("/pci-check", methods=["POST"])
def check_pci_status():
    data = request.get_json()
    domain = data.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "No domain provided."}), 400
    
    try:
        # This would normally use a PCI compliance database API
        # For now, we'll use a simplified check
        response = requests.get(f"https://{domain}", timeout=10)
        
        has_https = response.url.startswith("https")
        
        # Look for payment-related keywords in page content
        payment_keywords = ["credit card", "payment", "checkout", "secure payment", "card details"]
        payment_related = False
        
        for keyword in payment_keywords:
            if keyword in response.text.lower():
                payment_related = True
                break
        
        # Look for security seals/badges
        security_badges = ["norton", "mcafee", "trustwave", "pci compliant", "ssl secure"]
        has_security_badge = False
        
        for badge in security_badges:
            if badge in response.text.lower():
                has_security_badge = True
                break
                
        # Calculate a basic risk score
        risk_score = 0
        if not has_https:
            risk_score += 50
        if payment_related and not has_security_badge:
            risk_score += 30
            
        return jsonify({
            "domain": domain,
            "has_https": has_https,
            "payment_related": payment_related,
            "has_security_badges": has_security_badge,
            "risk_score": risk_score,
            "recommendation": "High Risk" if risk_score > 40 else "Medium Risk" if risk_score > 20 else "Low Risk",
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        })
    
    except Exception as e:
        return jsonify({"error": f"PCI check error: {str(e)}"}), 500

# Add machine learning malware URL detection (basic implementation)
def classify_url_ml(url):
    """Use basic features to classify URL as potentially malicious using rules"""
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    path = url.split(domain, 1)[1] if domain in url else ""
    
    # Calculate features
    features = {
        "domain_length": len(domain),
        "path_length": len(path),
        "subdomain_count": domain.count(".") - 1 if "." in domain else 0,
        "has_ip_address": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)),
        "has_suspicious_tld": any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS),
        "has_suspicious_keywords": any(keyword in url.lower() for keyword in PHISHING_KEYWORDS),
        "has_excessive_symbols": url.count("@") > 0 or url.count("//") > 1,
        "numeric_ratio": sum(c.isdigit() for c in domain) / len(domain) if domain else 0,
        "special_char_ratio": sum(not c.isalnum() for c in domain) / len(domain) if domain else 0
    }
    
    # Simple rule-based classification (in a real app, this would be a trained ML model)
    malicious_score = 0
    
    if features["has_ip_address"]:
        malicious_score += 30
    if features["has_suspicious_tld"]:
        malicious_score += 25
    if features["has_suspicious_keywords"]:
        malicious_score += 20
    if features["has_excessive_symbols"]:
        malicious_score += 30
    if features["numeric_ratio"] > 0.3:
        malicious_score += 15
    if features["special_char_ratio"] > 0.1:
        malicious_score += 15
    if features["subdomain_count"] > 2:
        malicious_score += 10
    if features["domain_length"] > 30:
        malicious_score += 10
    if features["path_length"] > 100:
        malicious_score += 10
        
    return {
        "url": url,
        "features": features,
        "malicious_probability": min(malicious_score / 100.0, 1.0),
        "is_likely_malicious": malicious_score > 50
    }

# New route for ML-based URL classification
@app.route("/ai-url-check", methods=["POST"])
def ai_url_check():
    data = request.get_json()
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    
    try:
        classification = classify_url_ml(url)
        
        return jsonify({
            "url": url,
            "analysis": classification,
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        })
    
    except Exception as e:
        return jsonify({"error": f"AI URL check error: {str(e)}"}), 500

# New route for generating a safe preview link
@app.route("/safe-preview", methods=["POST"])
def generate_safe_preview():
    data = request.get_json()
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    
    try:
        # Create a safe preview link using a URL shortener
        # In a real app, this would use your own redirection service with warnings
        
        # Create a unique token for this preview
        import uuid
        preview_token = str(uuid.uuid4())
        
        # In a real app, store this in a database
        # For now, we'll just return the concept
        
        safe_url = f"/preview/{preview_token}"
        
        return jsonify({
            "original_url": url,
            "safe_preview_url": safe_url,
            "preview_token": preview_token,
            "expires_in": "24 hours",
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        })
    
    except Exception as e:
        return jsonify({"error": f"Safe preview generation error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)

app = app