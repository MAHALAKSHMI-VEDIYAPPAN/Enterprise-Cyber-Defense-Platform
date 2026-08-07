import requests
from flask import current_app


def check_ip_reputation(ip_address):

    api_key = current_app.config["VIRUSTOTAL_API_KEY"]

    headers = {
        "x-apikey": api_key
    }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    try:

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return {
                "success": False,
                "message": "Unable to retrieve data from VirusTotal."
            }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "success": True,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"]
        }

    except Exception as e:

        return {
            "success": False,
            "message": str(e)
        }