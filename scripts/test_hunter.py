import requests

API_KEY = "6cae67b91ae525e8911189dc04c603a0e1f0c6e6"
domain = "cloudflare.com"  # Or "google.com", "apple.com"

url = "https://api.hunter.io/v2/domain-search"
params = {"api_key": API_KEY, "domain": domain}

response = requests.get(url, params=params)
data = response.json()

emails = data.get("data", {}).get("emails", [])

print(f"Found {len(emails)} emails for {domain}:\n")
for email in emails:
    print(f"Email: {email.get('value')}")
    print(f"  Name: {email.get('first_name', '')} {email.get('last_name', '')}")
    print(f"  Position: {email.get('position', 'Unknown')}")
    print(f"  Confidence: {email.get('confidence', 0)}%")
    print("-" * 40)