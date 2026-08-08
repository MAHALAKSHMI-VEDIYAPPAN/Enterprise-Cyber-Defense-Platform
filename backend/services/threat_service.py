import ipaddress
import requests

from flask import current_app


# ==========================================================
# VirusTotal IP Reputation
# ==========================================================

def check_ip_reputation(ip_address):
    """
    Check an IPv4/IPv6 address using the VirusTotal API.

    Returns a dictionary containing:
        - success
        - malicious
        - suspicious
        - harmless
        - undetected
        - total
        - risk_level
    """

    # ------------------------------------------------------
    # Validate IP Address
    # ------------------------------------------------------

    try:

        ipaddress.ip_address(ip_address)

    except ValueError:

        return {
            "success": False,
            "message": "Please enter a valid IP address."
        }

    # ------------------------------------------------------
    # Get API Key
    # ------------------------------------------------------

    api_key = current_app.config.get(
        "VIRUSTOTAL_API_KEY"
    )

    if not api_key:

        return {
            "success": False,
            "message": "VirusTotal API key is not configured."
        }

    # ------------------------------------------------------
    # VirusTotal API
    # ------------------------------------------------------

    url = (
        "https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip_address}"
    )

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        # --------------------------------------------------
        # HTTP Response Handling
        # --------------------------------------------------

        if response.status_code == 404:

            return {
                "success": False,
                "message": "No VirusTotal information was found for this IP address."
            }

        if response.status_code == 401:

            return {
                "success": False,
                "message": "VirusTotal API authentication failed."
            }

        if response.status_code == 403:

            return {
                "success": False,
                "message": "VirusTotal API access was denied."
            }

        if response.status_code == 429:

            return {
                "success": False,
                "message": "VirusTotal API rate limit reached. Please try again later."
            }

        if response.status_code != 200:

            return {
                "success": False,
                "message": (
                    "Unable to retrieve information from VirusTotal."
                )
            }

        # --------------------------------------------------
        # Parse Response
        # --------------------------------------------------

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        harmless = stats.get(
            "harmless",
            0
        )

        undetected = stats.get(
            "undetected",
            0
        )

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        # --------------------------------------------------
        # Risk Classification
        # --------------------------------------------------

        if malicious > 0:

            risk_level = "High"

        elif suspicious > 0:

            risk_level = "Medium"

        else:

            risk_level = "Low"

        # --------------------------------------------------
        # Return Result
        # --------------------------------------------------

        return {
            "success": True,
            "ip": ip_address,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "risk_level": risk_level
        }

    # ------------------------------------------------------
    # Timeout
    # ------------------------------------------------------

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "message": "VirusTotal request timed out."
        }

    # ------------------------------------------------------
    # Connection Error
    # ------------------------------------------------------

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "message": "Unable to connect to VirusTotal."
        }

    # ------------------------------------------------------
    # General Error
    # ------------------------------------------------------

    except requests.exceptions.RequestException:

        return {
            "success": False,
            "message": "A network error occurred while contacting VirusTotal."
        }

    except Exception:

        return {
            "success": False,
            "message": "An unexpected error occurred during threat analysis."
        }