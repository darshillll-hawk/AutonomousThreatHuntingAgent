import requests
import json

# Your Slack Webhook URL
slack_url = "" #use your own Slack Wehbook URl

# Function to send message to Slack
def send_to_slack(message):
    payload = {
        "text": message
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(slack_url, data=json.dumps(payload), headers=headers)
    
    if response.status_code == 200:
        print("✅ Message sent to Slack successfully!")
    else:
        print(f"❌ Failed to send message: {response.status_code}, {response.text}")

# Example usage
send_to_slack("🚨 Suspicious activity detected: Multiple failed login attempts on server.")

