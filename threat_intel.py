# threat_intel.py
import requests
from config import ABUSEIPDB_API_KEY

def get_ip_reputation(ip_address):
    """Checks an IP's reputation score. Higher score = more malicious."""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "PASTE_YOUR_ABUSEIPDB_API_KEY_HERE":
        return None # Skip if no API key

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={'ipAddress': ip_address},
        headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    )
    if response.status_code == 200:
        return response.json()['data']
    return None
