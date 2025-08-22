import pandas as pd
import requests
import os
from openai import OpenAI

# ---- CONFIG ----
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY_HERE"  # Replace with your AbuseIPDB key
OPENAI_API_KEY = "" #Use your own OPEN_AI_KEY

client = OpenAI(api_key=OPENAI_API_KEY)

# ---- STEP 1: Load logs ----
df = pd.read_json("../logs/sample_logs.json")

def is_suspicious(event, ip):
    if "Failed SSH Login" in event:
        return True
    if not (ip.startswith("192.") or ip.startswith("10.")):
        return True
    return False

df["suspicious"] = df.apply(lambda row: is_suspicious(row["event"], row["source_ip"]), axis=1)
suspicious_ips = df[df["suspicious"] == True]["source_ip"].unique()

# ---- STEP 2: Threat intel enrichment ----
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        data = response.json()["data"]
        return data["abuseConfidenceScore"], data["totalReports"], data.get("countryCode", "N/A")
    return None, None, None

enriched_results = []
for ip in suspicious_ips:
    score, reports, country = check_ip(ip)
    enriched_results.append({
        "ip": ip,
        "score": score,
        "reports": reports,
        "country": country
    })

# ---- STEP 3: Generate AI incident report ----
report_prompt = f"""
You are a cybersecurity SOC analyst.
Summarize the following suspicious IP activity in clear incident report style.
Include: risk level, source country, type of threat, and recommendation.

Data: {enriched_results}
"""

response = client.responses.create(
    model="gpt-4.1-mini",
    input=report_prompt
)

incident_report = response.output_text

# ---- STEP 4: Save & display ----
with open("../logs/incident_report.txt", "w") as f:
    f.write(incident_report)

print("Incident Report Generated:\n")
print(incident_report)

