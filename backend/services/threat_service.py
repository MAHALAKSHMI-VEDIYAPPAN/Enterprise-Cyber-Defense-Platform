import ipaddress
import requests

from flask import current_app


# ==========================================================
# VirusTotal IP Threat Intelligence
# ==========================================================

def check_ip_reputation(ip_address):
    """
    Analyze an IPv4/IPv6 address using the VirusTotal API.

    Returns a structured threat intelligence result containing:

        - success
        - ip
        - malicious
        - suspicious
        - harmless
        - undetected
        - timeout
        - total
        - detection_rate
        - risk_level
        - risk_score
        - reputation
        - country
        - continent
        - asn
        - as_owner
        - network
        - regional_internet_registry
        - tags
        - community_votes
        - message
    """

    # ======================================================
    # Validate IP Address
    # ======================================================

    ip_address = ip_address.strip()

    try:

        validated_ip = ipaddress.ip_address(
            ip_address
        )

        ip_address = str(validated_ip)

    except ValueError:

        return {
            "success": False,
            "message": "Please enter a valid IPv4 or IPv6 address."
        }


    # ======================================================
    # Get VirusTotal API Key
    # ======================================================

    api_key = current_app.config.get(
        "VIRUSTOTAL_API_KEY"
    )


    if not api_key:

        return {
            "success": False,
            "message": (
                "VirusTotal API key is not configured."
            )
        }


    # ======================================================
    # VirusTotal IP API
    # ======================================================

    url = (
        "https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip_address}"
    )


    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }


    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )


        # ==================================================
        # HTTP Response Handling
        # ==================================================

        if response.status_code == 400:

            return {
                "success": False,
                "message": (
                    "VirusTotal rejected the IP address "
                    "request."
                )
            }


        if response.status_code == 401:

            return {
                "success": False,
                "message": (
                    "VirusTotal API authentication failed. "
                    "Check your API key."
                )
            }


        if response.status_code == 403:

            return {
                "success": False,
                "message": (
                    "VirusTotal API access was denied."
                )
            }


        if response.status_code == 404:

            return {
                "success": False,
                "message": (
                    "No VirusTotal information was found "
                    "for this IP address."
                )
            }


        if response.status_code == 429:

            return {
                "success": False,
                "message": (
                    "VirusTotal API rate limit reached. "
                    "Please try again later."
                )
            }


        if response.status_code != 200:

            return {
                "success": False,
                "message": (
                    "Unable to retrieve threat intelligence "
                    "from VirusTotal."
                )
            }


        # ==================================================
        # Parse JSON Response
        # ==================================================

        data = response.json()


        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )


        # ==================================================
        # Analysis Statistics
        # ==================================================

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )


        malicious = int(
            stats.get(
                "malicious",
                0
            )
            or 0
        )


        suspicious = int(
            stats.get(
                "suspicious",
                0
            )
            or 0
        )


        harmless = int(
            stats.get(
                "harmless",
                0
            )
            or 0
        )


        undetected = int(
            stats.get(
                "undetected",
                0
            )
            or 0
        )


        timeout = int(
            stats.get(
                "timeout",
                0
            )
            or 0
        )


        # ==================================================
        # Total Analysis Engines
        # ==================================================

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )


        # ==================================================
        # Detection Rate
        # ==================================================

        detection_count = (
            malicious
            + suspicious
        )


        if total > 0:

            detection_rate = round(
                (
                    detection_count
                    / total
                ) * 100,
                2
            )

        else:

            detection_rate = 0.0


        # ==================================================
        # Threat Risk Score
        # ==================================================
        #
        # This is an ECDP application-level score.
        # It is NOT a VirusTotal official score.
        #
        # Maximum = 100
        #
        # Malicious detections have the highest weight.
        # Suspicious detections have a lower weight.
        # ==================================================

        risk_score = 0


        if total > 0:

            risk_score = round(
                (
                    (
                        malicious * 100
                    )
                    + (
                        suspicious * 50
                    )
                )
                / total
            )


        risk_score = max(
            0,
            min(
                100,
                risk_score
            )
        )


        # ==================================================
        # Risk Classification
        # ==================================================

        if malicious >= 5:

            risk_level = "Critical"

        elif malicious > 0:

            risk_level = "High"

        elif suspicious >= 3:

            risk_level = "Medium"

        elif suspicious > 0:

            risk_level = "Low"

        else:

            risk_level = "Low"


        # ==================================================
        # IP Metadata
        # ==================================================

        country = attributes.get(
            "country",
            "Unknown"
        )


        continent = attributes.get(
            "continent",
            "Unknown"
        )


        asn = attributes.get(
            "asn",
            "Unknown"
        )


        as_owner = attributes.get(
            "as_owner",
            "Unknown"
        )


        network = attributes.get(
            "network",
            "Unknown"
        )


        regional_internet_registry = (
            attributes.get(
                "regional_internet_registry",
                "Unknown"
            )
        )


        reputation = attributes.get(
            "reputation",
            0
        )


        # ==================================================
        # Community Votes
        # ==================================================

        total_votes = attributes.get(
            "total_votes",
            {}
        )


        community_harmless = int(
            total_votes.get(
                "harmless",
                0
            )
            or 0
        )


        community_malicious = int(
            total_votes.get(
                "malicious",
                0
            )
            or 0
        )


        # ==================================================
        # Tags
        # ==================================================

        tags = attributes.get(
            "tags",
            []
        )


        if not isinstance(tags, list):

            tags = []


        # ==================================================
        # Last Analysis Date
        # ==================================================

        last_analysis_date = attributes.get(
            "last_analysis_date"
        )


        # ==================================================
        # Last Modification Date
        # ==================================================

        last_modification_date = attributes.get(
            "last_modification_date"
        )


        # ==================================================
        # WHOIS Information
        # ==================================================

        whois = attributes.get(
            "whois",
            ""
        )


        # Keep WHOIS optional so we don't expose
        # unnecessary large data in the dashboard.

        whois_available = bool(
            whois
        )


        # ==================================================
        # Threat Assessment Message
        # ==================================================

        if risk_level == "Critical":

            assessment = (
                "Critical threat indicators detected. "
                "Immediate investigation and containment "
                "are recommended."
            )

        elif risk_level == "High":

            assessment = (
                "Malicious activity has been detected. "
                "The IP address should be investigated "
                "and blocked if confirmed malicious."
            )

        elif risk_level == "Medium":

            assessment = (
                "Suspicious activity has been detected. "
                "Additional investigation is recommended."
            )

        else:

            assessment = (
                "No significant malicious activity was "
                "detected by the available VirusTotal "
                "analysis engines."
            )


        # ==================================================
        # Final Result
        # ==================================================

        return {

            "success": True,

            # ----------------------------------------------
            # IP
            # ----------------------------------------------

            "ip": ip_address,


            # ----------------------------------------------
            # Detection Statistics
            # ----------------------------------------------

            "malicious": malicious,

            "suspicious": suspicious,

            "harmless": harmless,

            "undetected": undetected,

            "timeout": timeout,

            "total": total,


            # ----------------------------------------------
            # Detection Rate
            # ----------------------------------------------

            "detection_rate": detection_rate,


            # ----------------------------------------------
            # ECDP Risk
            # ----------------------------------------------

            "risk_level": risk_level,

            "risk_score": risk_score,


            # ----------------------------------------------
            # IP Intelligence
            # ----------------------------------------------

            "country": country,

            "continent": continent,

            "asn": asn,

            "as_owner": as_owner,

            "network": network,

            "regional_internet_registry": (
                regional_internet_registry
            ),


            # ----------------------------------------------
            # Reputation
            # ----------------------------------------------

            "reputation": reputation,


            # ----------------------------------------------
            # Community Votes
            # ----------------------------------------------

            "community_votes": {

                "harmless": community_harmless,

                "malicious": community_malicious
            },


            # ----------------------------------------------
            # Tags
            # ----------------------------------------------

            "tags": tags,


            # ----------------------------------------------
            # Analysis Information
            # ----------------------------------------------

            "last_analysis_date": (
                last_analysis_date
            ),

            "last_modification_date": (
                last_modification_date
            ),


            # ----------------------------------------------
            # WHOIS
            # ----------------------------------------------

            "whois_available": (
                whois_available
            ),


            # ----------------------------------------------
            # Analyst Assessment
            # ----------------------------------------------

            "assessment": assessment
        }


    # ======================================================
    # Timeout
    # ======================================================

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "message": (
                "VirusTotal request timed out. "
                "Please try again."
            )
        }


    # ======================================================
    # Connection Error
    # ======================================================

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "message": (
                "Unable to connect to VirusTotal. "
                "Check your internet connection."
            )
        }


    # ======================================================
    # JSON Error
    # ======================================================

    except ValueError:

        return {
            "success": False,
            "message": (
                "VirusTotal returned an invalid response."
            )
        }


    # ======================================================
    # Request Error
    # ======================================================

    except requests.exceptions.RequestException:

        return {
            "success": False,
            "message": (
                "A network error occurred while contacting "
                "VirusTotal."
            )
        }


    # ======================================================
    # Unexpected Error
    # ======================================================

    except Exception:

     return {
        "success": False,
        "message": (
            "An unexpected error occurred during "
            "threat analysis."
        )
    }