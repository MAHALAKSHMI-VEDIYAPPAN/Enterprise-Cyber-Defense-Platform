import ipaddress
import time
from datetime import datetime, timezone

import requests

from flask import current_app


# ==========================================================
# VirusTotal Configuration
# ==========================================================

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ==========================================================
# Validate IP Address
# ==========================================================

def validate_ip(ip_address):

    if not isinstance(ip_address, str):
        return (
            False,
            "Target must be a valid IP address."
        )

    ip_address = ip_address.strip()

    if not ip_address:
        return (
            False,
            "IP address cannot be empty."
        )

    try:

        validated_ip = ipaddress.ip_address(
            ip_address
        )

        return (
            True,
            str(validated_ip)
        )

    except ValueError:

        return (
            False,
            "Please enter a valid IPv4 or IPv6 address."
        )


# ==========================================================
# Get VirusTotal API Key
# ==========================================================

def get_api_key():

    return current_app.config.get(
        "VIRUSTOTAL_API_KEY"
    )


# ==========================================================
# Get IP Report
# ==========================================================

def get_ip_report(
    ip_address,
    api_key
):

    url = (
        f"{VT_BASE_URL}/ip_addresses/"
        f"{ip_address}"
    )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=20
    )

    return response


# ==========================================================
# Request Fresh IP Analysis
# ==========================================================

def request_ip_reanalysis(
    ip_address,
    api_key
):

    url = (
        f"{VT_BASE_URL}/ip_addresses/"
        f"{ip_address}/analyse"
    )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    response = requests.post(
        url,
        headers=headers,
        timeout=20
    )

    return response


# ==========================================================
# Get Analysis Result
# ==========================================================

def get_analysis(
    analysis_id,
    api_key
):

    url = (
        f"{VT_BASE_URL}/analyses/"
        f"{analysis_id}"
    )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=20
    )

    return response


# ==========================================================
# Format Unix Timestamp
# ==========================================================

def format_timestamp(timestamp):

    if not timestamp:
        return "Unknown"

    try:

        timestamp = int(timestamp)

        readable_time = datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc
        )

        return readable_time.strftime(
            "%d %b %Y, %H:%M UTC"
        )

    except (
        ValueError,
        TypeError,
        OverflowError
    ):

        return "Unknown"


# ==========================================================
# Refresh VirusTotal Analysis
# ==========================================================

def refresh_ip_intelligence(
    ip_address,
    api_key
):

    try:

        response = request_ip_reanalysis(
            ip_address,
            api_key
        )

        if response.status_code not in [
            200,
            201
        ]:

            return {
                "success": False,
                "message": (
                    "VirusTotal could not start "
                    "a fresh IP analysis."
                )
            }

        data = response.json()

        analysis_id = (
            data
            .get("data", {})
            .get("id")
        )

        if not analysis_id:

            return {
                "success": False,
                "message": (
                    "VirusTotal did not return "
                    "an analysis ID."
                )
            }

        # --------------------------------------------------
        # Poll Analysis
        # --------------------------------------------------

        for _ in range(6):

            time.sleep(2)

            analysis_response = get_analysis(
                analysis_id,
                api_key
            )

            if analysis_response.status_code != 200:
                continue

            analysis_data = (
                analysis_response
                .json()
                .get("data", {})
                .get("attributes", {})
            )

            status = analysis_data.get(
                "status"
            )

            if status == "completed":

                return {
                    "success": True,
                    "analysis_id": analysis_id
                }

        return {
            "success": False,
            "message": (
                "VirusTotal analysis is still "
                "processing. Using the latest "
                "available intelligence."
            )
        }

    except requests.exceptions.RequestException:

        return {
            "success": False,
            "message": (
                "Unable to refresh VirusTotal "
                "analysis."
            )
        }


# ==========================================================
# Calculate ECDP Risk
# ==========================================================

def calculate_risk(
    malicious,
    suspicious,
    total,
    reputation,
    community_malicious,
    community_harmless,
    tags
):

    # ======================================================
    # Detection Component
    # ======================================================

    detection_score = 0

    if total > 0:

        detection_score = (
            (
                malicious * 100
            )
            +
            (
                suspicious * 60
            )
        ) / total

    # ======================================================
    # Community Component
    # ======================================================

    community_score = 0

    total_votes = (
        community_malicious
        +
        community_harmless
    )

    if total_votes > 0:

        malicious_vote_ratio = (
            community_malicious
            / total_votes
        )

        community_score = (
            malicious_vote_ratio * 100
        )

    # ======================================================
    # Reputation Component
    # ======================================================

    reputation_score = 0

    if reputation < 0:

        reputation_score = min(
            abs(reputation),
            100
        )

    # ======================================================
    # Threat Tag Component
    # ======================================================

    tag_score = 0

    suspicious_tags = {
        "malware",
        "malicious",
        "phishing",
        "botnet",
        "c2",
        "command-and-control",
        "tor",
        "scanner",
        "proxy",
        "spam",
        "abuse",
        "ransomware",
        "exploit",
        "bruteforce"
    }

    normalized_tags = {
        str(tag).lower().strip()
        for tag in tags
    }

    matching_tags = (
        normalized_tags
        & suspicious_tags
    )

    if matching_tags:

        tag_score = min(
            len(matching_tags) * 15,
            60
        )

    # ======================================================
    # Final Weighted Score
    # ======================================================

    risk_score = round(

        (
            detection_score * 0.60
        )
        +
        (
            community_score * 0.25
        )
        +
        (
            reputation_score * 0.10
        )
        +
        (
            tag_score * 0.05
        )

    )

    # ======================================================
    # Risk Classification
    # ======================================================

    # ------------------------------------------------------
    # Critical
    # ------------------------------------------------------

    if malicious >= 5:

        risk_level = "Critical"

    # ------------------------------------------------------
    # High
    # ------------------------------------------------------

    elif malicious >= 2:

        risk_level = "High"

    elif malicious == 1:

        risk_level = "High"

    elif suspicious >= 5:

        risk_level = "High"

    # ------------------------------------------------------
    # Community High-Risk Indicator
    # ------------------------------------------------------

    elif (
        community_malicious >= 25
        and total_votes > 0
        and (
            community_malicious / total_votes
        ) >= 0.30
    ):

        risk_level = "High"

    # ------------------------------------------------------
    # Medium
    # ------------------------------------------------------

    elif suspicious >= 2:

        risk_level = "Medium"

    elif suspicious == 1:

        risk_level = "Medium"

    elif (
        community_malicious >= 10
        and total_votes > 0
        and (
            community_malicious / total_votes
        ) >= 0.20
    ):

        risk_level = "Medium"

    elif reputation <= -10:

        risk_level = "Medium"

    elif tag_score >= 30:

        risk_level = "Medium"

    # ------------------------------------------------------
    # Low
    # ------------------------------------------------------

    else:

        risk_level = "Low"

    # ======================================================
    # Make Score Consistent With Classification
    # ======================================================

    if risk_level == "Critical":

        risk_score = max(
            risk_score,
            80
        )

    elif risk_level == "High":

        risk_score = max(
            risk_score,
            60
        )

    elif risk_level == "Medium":

        risk_score = max(
            risk_score,
            35
        )

    else:

        risk_score = min(
            risk_score,
            34
        )

    return (
        risk_level,
        min(
            max(
                risk_score,
                0
            ),
            100
        )
    )


# ==========================================================
# Threat Assessment Message
# ==========================================================

def build_assessment(
    risk_level,
    malicious,
    suspicious,
    reputation,
    community_malicious,
    community_harmless,
    tags
):

    reasons = []

    # ======================================================
    # Critical
    # ======================================================

    if risk_level == "Critical":

        if malicious > 0:

            reasons.append(
                f"{malicious} malicious security engine detections"
            )

        if suspicious > 0:

            reasons.append(
                f"{suspicious} suspicious security engine detections"
            )

        if community_malicious > 0:

            reasons.append(
                f"{community_malicious} malicious community votes"
            )

        return (
            "Critical threat indicators were detected. "
            + ", ".join(reasons)
            + ". Immediate investigation and containment "
              "are recommended."
        )

    # ======================================================
    # High
    # ======================================================

    if risk_level == "High":

        if malicious > 0:

            reasons.append(
                f"{malicious} malicious detection(s)"
            )

        if suspicious > 0:

            reasons.append(
                f"{suspicious} suspicious detection(s)"
            )

        if community_malicious > 0:

            reasons.append(
                f"{community_malicious} malicious community vote(s)"
            )

        if reputation < 0:

            reasons.append(
                "negative reputation"
            )

        if tags:

            matching_tags = {
                str(tag).lower().strip()
                for tag in tags
            }

            if matching_tags:

                reasons.append(
                    "threat intelligence tags"
                )

        reason_text = ", ".join(
            reasons
        )

        return (
            "High-risk indicators detected"
            + (
                f": {reason_text}."
                if reason_text
                else "."
            )
            + " Further investigation is recommended."
        )

    # ======================================================
    # Medium
    # ======================================================

    if risk_level == "Medium":

        if suspicious > 0:

            reasons.append(
                f"{suspicious} suspicious detection(s)"
            )

        if community_malicious > 0:

            reasons.append(
                f"{community_malicious} malicious community vote(s)"
            )

        if reputation < 0:

            reasons.append(
                "negative community reputation"
            )

        if tags:

            reasons.append(
                "threat-related intelligence tags"
            )

        reason_text = ", ".join(
            reasons
        )

        return (
            "Moderate threat indicators detected"
            + (
                f": {reason_text}."
                if reason_text
                else "."
            )
            + " Additional investigation is recommended."
        )

    # ======================================================
    # Low
    # ======================================================

    return (
        "No significant malicious activity was "
        "identified by the available VirusTotal "
        "intelligence."
    )


# ==========================================================
# Main Threat Intelligence Function
# ==========================================================

def check_ip_reputation(
    ip_address
):

    # ======================================================
    # Validate IP
    # ======================================================

    valid, normalized_ip = validate_ip(
        ip_address
    )

    if not valid:

        return {
            "success": False,
            "message": normalized_ip
        }

    ip_address = normalized_ip

    # ======================================================
    # API Key
    # ======================================================

    api_key = get_api_key()

    if not api_key:

        return {
            "success": False,
            "message": (
                "VirusTotal API key is not configured."
            )
        }

    # ======================================================
    # Get Existing Intelligence
    # ======================================================

    try:

        response = get_ip_report(
            ip_address,
            api_key
        )

        # --------------------------------------------------
        # HTTP Errors
        # --------------------------------------------------

        if response.status_code == 400:

            return {
                "success": False,
                "message": (
                    "VirusTotal rejected the IP address."
                )
            }

        if response.status_code == 401:

            return {
                "success": False,
                "message": (
                    "VirusTotal API authentication failed."
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
                    "VirusTotal API rate limit reached."
                )
            }

        if response.status_code != 200:

            return {
                "success": False,
                "message": (
                    "Unable to retrieve threat intelligence."
                )
            }

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        # ==================================================
        # Optional Fresh Analysis
        # ==================================================

        refresh_enabled = current_app.config.get(
            "VIRUSTOTAL_REFRESH_ANALYSIS",
            False
        )

        refresh_status = None

        if refresh_enabled:

            refresh_status = refresh_ip_intelligence(
                ip_address,
                api_key
            )

            # ------------------------------------------------
            # Retrieve Updated Report
            # ------------------------------------------------

            if refresh_status.get("success"):

                refreshed_response = get_ip_report(
                    ip_address,
                    api_key
                )

                if refreshed_response.status_code == 200:

                    refreshed_data = (
                        refreshed_response
                        .json()
                    )

                    attributes = (
                        refreshed_data
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
        # Metadata
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

        reputation = int(
            attributes.get(
                "reputation",
                0
            )
            or 0
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

        if not isinstance(
            tags,
            list
        ):

            tags = []

        # ==================================================
        # Dates
        # ==================================================

        last_analysis_date = (
            attributes.get(
                "last_analysis_date"
            )
        )

        last_modification_date = (
            attributes.get(
                "last_modification_date"
            )
        )

        # Human-readable versions
        last_analysis_readable = format_timestamp(
            last_analysis_date
        )

        last_modification_readable = format_timestamp(
            last_modification_date
        )

        # ==================================================
        # WHOIS
        # ==================================================

        whois = attributes.get(
            "whois",
            ""
        )

        whois_available = bool(
            whois
        )

        # ==================================================
        # ECDP Risk
        # ==================================================

        risk_level, risk_score = calculate_risk(

            malicious,
            suspicious,
            total,
            reputation,
            community_malicious,
            community_harmless,
            tags

        )

        # ==================================================
        # Assessment
        # ==================================================

        assessment = build_assessment(

            risk_level,
            malicious,
            suspicious,
            reputation,
            community_malicious,
            community_harmless,
            tags

        )

        # ==================================================
        # Intelligence Status
        # ==================================================

        if (
            refresh_status
            and refresh_status.get("success")
        ):

            intelligence_status = (
                "Fresh VirusTotal Analysis"
            )

        else:

            intelligence_status = (
                "Latest Available VirusTotal Report"
            )

        # ==================================================
        # Final Result
        # ==================================================

        return {

            "success": True,

            "ip": ip_address,

            "malicious": malicious,

            "suspicious": suspicious,

            "harmless": harmless,

            "undetected": undetected,

            "timeout": timeout,

            "total": total,

            "detection_rate": detection_rate,

            "risk_level": risk_level,

            "risk_score": risk_score,

            "reputation": reputation,

            "country": country,

            "continent": continent,

            "asn": asn,

            "as_owner": as_owner,

            "network": network,

            "regional_internet_registry": (
                regional_internet_registry
            ),

            "community_votes": {

                "harmless": community_harmless,

                "malicious": community_malicious

            },

            "tags": tags,

            "last_analysis_date": (
                last_analysis_date
            ),

            "last_analysis_readable": (
                last_analysis_readable
            ),

            "last_modification_date": (
                last_modification_date
            ),

            "last_modification_readable": (
                last_modification_readable
            ),

            "whois_available": (
                whois_available
            ),

            "refresh_attempted": (
                refresh_enabled
            ),

            "refresh_completed": (
                bool(
                    refresh_status
                    and refresh_status.get("success")
                )
            ),

            "intelligence_status": (
                intelligence_status
            ),

            "assessment": assessment
        }

    # ======================================================
    # Timeout
    # ======================================================

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "message": (
                "VirusTotal request timed out."
            )
        }

    # ======================================================
    # Connection Error
    # ======================================================

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "message": (
                "Unable to connect to VirusTotal."
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

    except requests.exceptions.RequestException as error:

        return {
            "success": False,
            "message": (
                f"VirusTotal request error: {str(error)}"
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