import pandas as pd
import requests

API_KEY = "YOUR_API_KEY_HERE"  # Replace with your AbuseIPDB API key

# Load suspicious IPs from Step 2 results
df = pd.read_json("../logs/sample_logs.json")

# Simple suspicious check (from Step 2)
def is_suspicious(event, ip):
    if "Failed SSH Login" in event:
        return True
    if not (ip.startswith("192.") or ip.startswith("10.")):
        return True
    return False

df["suspicious"] = df.apply(lambda row: is_suspicious(row["event"], row["source_ip"]), axis=1)
suspicious_ips = df[df["suspicious"] == True]["source_ip"].unique()

print(f"Found {len(suspicious_ips)} suspicious IP(s)")

# Function to query AbuseIPDB
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        data = response.json()["data"]
        return data["abuseConfidenceScore"], data["totalReports"], data.get("countryCode", "N/A")
    else:
        return None, None, None

# Check each suspicious IP
for ip in suspicious_ips:
    score, reports, country = check_ip(ip)
    if score is not None:
        print(f"IP: {ip} | Score: {score} | Reports: {reports} | Country: {country}")
    else:
        print(f"IP: {ip} | Could not retrieve data")
