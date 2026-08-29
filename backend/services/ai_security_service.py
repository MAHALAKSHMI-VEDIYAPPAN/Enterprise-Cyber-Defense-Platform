import json

from models.asset import Asset
from models.scan import Scan
from models.incident import Incident
from models.remediation import Remediation


# ==========================================================
# Collect ECDP Security Context
# ==========================================================

def get_ecdp_context():

    total_assets = Asset.query.count()

    active_assets = Asset.query.filter_by(
        status="Active"
    ).count()

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(
            ["High", "Critical"]
        )
    ).count()

    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(
        status="Completed"
    ).count()

    failed_scans = Scan.query.filter(
        Scan.status != "Completed"
    ).count()

    total_incidents = Incident.query.count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    critical_incidents = Incident.query.filter_by(
        severity="Critical"
    ).count()

    high_incidents = Incident.query.filter_by(
        severity="High"
    ).count()

    medium_incidents = Incident.query.filter_by(
        severity="Medium"
    ).count()

    low_incidents = Incident.query.filter_by(
        severity="Low"
    ).count()

    total_remediations = Remediation.query.count()

    open_remediations = Remediation.query.filter_by(
        status="Open"
    ).count()

    in_progress_remediations = Remediation.query.filter_by(
        status="In Progress"
    ).count()

    resolved_remediations = Remediation.query.filter_by(
        status="Resolved"
    ).count()

    verified_remediations = Remediation.query.filter_by(
        status="Verified"
    ).count()

    return {

        "assets": {
            "total": total_assets,
            "active": active_assets,
            "high_risk": high_risk_assets
        },

        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "failed": failed_scans
        },

        "incidents": {
            "total": total_incidents,
            "open": open_incidents,
            "critical": critical_incidents,
            "high": high_incidents,
            "medium": medium_incidents,
            "low": low_incidents
        },

        "remediations": {
            "total": total_remediations,
            "open": open_remediations,
            "in_progress": in_progress_remediations,
            "resolved": resolved_remediations,
            "verified": verified_remediations
        }
    }


# ==========================================================
# Calculate Security Score
# ==========================================================

def calculate_security_score(context):

    total_assets = context["assets"]["total"]

    high_risk_assets = context["assets"]["high_risk"]

    open_incidents = context["incidents"]["open"]

    critical_incidents = context["incidents"]["critical"]

    score = 100


    if total_assets > 0:

        risk_percentage = (
            high_risk_assets /
            total_assets
        ) * 100

        score -= min(
            risk_percentage * 0.30,
            30
        )


    score -= min(
        critical_incidents * 10,
        30
    )


    score -= min(
        open_incidents * 3,
        20
    )


    return max(
        0,
        min(
            100,
            round(score)
        )
    )


# ==========================================================
# Generate Security Analysis
# ==========================================================

def generate_security_analysis():

    context = get_ecdp_context()

    score = calculate_security_score(
        context
    )


    # ======================================================
    # Risk Level
    # ======================================================

    if score >= 80:

        risk_level = "Low"

    elif score >= 60:

        risk_level = "Moderate"

    elif score >= 40:

        risk_level = "High"

    else:

        risk_level = "Critical"


    # ======================================================
    # Recommendations
    # ======================================================

    recommendations = []


    if context["assets"]["high_risk"] > 0:

        recommendations.append(
            "Prioritize remediation of high or "
            "critical-risk assets."
        )


    if context["incidents"]["open"] > 0:

        recommendations.append(
            "Investigate and resolve all open "
            "security incidents."
        )


    if context["incidents"]["critical"] > 0:

        recommendations.append(
            "Immediately investigate critical "
            "security incidents."
        )


    if context["scans"]["failed"] > 0:

        recommendations.append(
            "Investigate failed vulnerability scans."
        )


    if context["remediations"]["open"] > 0:

        recommendations.append(
            "Prioritize open remediation tasks."
        )


    if not recommendations:

        recommendations.append(
            "Continue regular vulnerability scanning "
            "and security monitoring."
        )


    # ======================================================
    # Summary
    # ======================================================

    if risk_level == "Low":

        summary = (
            "The current security posture is healthy. "
            "Continue regular monitoring and scanning."
        )

    elif risk_level == "Moderate":

        summary = (
            "The environment has some security concerns "
            "that should be reviewed and addressed."
        )

    elif risk_level == "High":

        summary = (
            "The environment has significant security "
            "risks. Immediate remediation is recommended."
        )

    else:

        summary = (
            "The environment is in a critical security "
            "state. Immediate investigation is required."
        )


    # ======================================================
    # Return Dashboard-Compatible Structure
    # ======================================================

    return {

        "score": score,

        "risk_level": risk_level,

        "summary": summary,

        "statistics": {

            "total_assets":
                context["assets"]["total"],

            "active_assets":
                context["assets"]["active"],

            "high_risk_assets":
                context["assets"]["high_risk"],

            "total_scans":
                context["scans"]["total"],

            "completed_scans":
                context["scans"]["completed"],

            "failed_scans":
                context["scans"]["failed"],

            "total_incidents":
                context["incidents"]["total"],

            "open_incidents":
                context["incidents"]["open"],

            "critical_incidents":
                context["incidents"]["critical"],

            "high_incidents":
                context["incidents"]["high"],

            "medium_incidents":
                context["incidents"]["medium"],

            "low_incidents":
                context["incidents"]["low"],

            "total_remediations":
                context["remediations"]["total"],

            "open_remediations":
                context["remediations"]["open"],

            "in_progress_remediations":
                context["remediations"]["in_progress"],

            "resolved_remediations":
                context["remediations"]["resolved"],

            "verified_remediations":
                context["remediations"]["verified"]

        },

        "recommendations":
            recommendations

    }


# ==========================================================
# ECDP Security Assistant
# ==========================================================

def ask_security_ai(question):

    if not question:

        return (
            "Please enter a cybersecurity question."
        )


    question = question.strip()


    if not question:

        return (
            "Please enter a cybersecurity question."
        )


    question_lower = question.lower()


    # ======================================================
    # Get Current ECDP Data
    # ======================================================

    try:

        context = get_ecdp_context()

        score = calculate_security_score(
            context
        )

    except Exception as error:

        print(
            "[AI SECURITY] Context error:",
            str(error)
        )

        return (
            "Unable to analyze the current "
            "ECDP security environment."
        )


    # ======================================================
    # Security Score
    # ======================================================

    if (
        "security score" in question_lower
        or "score" in question_lower
    ):

        return (
            f"CURRENT SECURITY SCORE\n\n"
            f"Security Score: {score}/100\n\n"
            f"Risk Level: "
            f"{get_risk_level(score)}\n\n"
            f"The score is calculated using the current "
            f"asset risk and incident information in ECDP."
        )


    # ======================================================
    # Highest Security Risks
    # ======================================================

    if (
        "highest security risks" in question_lower
        or "main security risks" in question_lower
        or "biggest security risks" in question_lower
        or "security risks" in question_lower
    ):

        return (
            "HIGHEST CURRENT SECURITY RISKS\n\n"

            f"High/Critical-risk assets: "
            f"{context['assets']['high_risk']}\n"

            f"Open incidents: "
            f"{context['incidents']['open']}\n"

            f"Critical incidents: "
            f"{context['incidents']['critical']}\n\n"

            "Recommended action:\n"

            "1. Investigate Critical and High incidents.\n"
            "2. Review High/Critical-risk assets.\n"
            "3. Complete pending remediation tasks.\n"
            "4. Investigate failed vulnerability scans."
        )


    # ======================================================
    # Open Incidents
    # ======================================================

    if (
        "open incidents" in question_lower
        or "how many incidents" in question_lower
    ):

        return (
            "CURRENT INCIDENT STATUS\n\n"

            f"Total incidents: "
            f"{context['incidents']['total']}\n"

            f"Open incidents: "
            f"{context['incidents']['open']}\n"

            f"Critical: "
            f"{context['incidents']['critical']}\n"

            f"High: "
            f"{context['incidents']['high']}\n"

            f"Medium: "
            f"{context['incidents']['medium']}\n"

            f"Low: "
            f"{context['incidents']['low']}\n\n"

            "Priority: investigate Critical and High "
            "severity incidents first."
        )


    # ======================================================
    # Asset Status
    # ======================================================

    if (
        "asset status" in question_lower
        or "assets" in question_lower
        or "asset count" in question_lower
    ):

        return (
            "CURRENT ASSET STATUS\n\n"

            f"Total assets: "
            f"{context['assets']['total']}\n"

            f"Active assets: "
            f"{context['assets']['active']}\n"

            f"High/Critical-risk assets: "
            f"{context['assets']['high_risk']}\n\n"

            "High and Critical-risk assets should be "
            "reviewed and remediated first."
        )


    # ======================================================
    # Scan Status
    # ======================================================

    if (
        "scan" in question_lower
        or "scans" in question_lower
        or "vulnerability scan" in question_lower
    ):

        return (
            "VULNERABILITY SCAN STATUS\n\n"

            f"Total scans: "
            f"{context['scans']['total']}\n"

            f"Completed scans: "
            f"{context['scans']['completed']}\n"

            f"Failed scans: "
            f"{context['scans']['failed']}\n\n"

            "Failed scans should be investigated to "
            "ensure that assets are being properly assessed."
        )


    # ======================================================
    # Remediation
    # ======================================================

    if (
        "remediation" in question_lower
        or "remediations" in question_lower
        or "fix first" in question_lower
        or "what should i fix" in question_lower
    ):

        return (
            "REMEDIATION PRIORITY\n\n"

            f"Total remediation tasks: "
            f"{context['remediations']['total']}\n"

            f"Open: "
            f"{context['remediations']['open']}\n"

            f"In Progress: "
            f"{context['remediations']['in_progress']}\n"

            f"Resolved: "
            f"{context['remediations']['resolved']}\n"

            f"Verified: "
            f"{context['remediations']['verified']}\n\n"

            "Recommended priority:\n"

            "1. Critical security issues\n"
            "2. High severity issues\n"
            "3. Internet-facing vulnerabilities\n"
            "4. Remaining medium-risk issues\n"
            "5. Low-risk findings"
        )


    # ======================================================
    # SQL Injection
    # ======================================================

    if (
        "sql injection" in question_lower
        or "sqli" in question_lower
    ):

        return (
            "SQL INJECTION PREVENTION\n\n"

            "To reduce SQL injection risk:\n\n"

            "1. Use parameterized queries or prepared "
            "statements instead of constructing SQL "
            "queries with user input.\n\n"

            "2. Validate input using appropriate "
            "allowlists and data types.\n\n"

            "3. Avoid dynamically constructing SQL "
            "statements from untrusted input.\n\n"

            "4. Use database accounts with the minimum "
            "permissions required by the application.\n\n"

            "5. Handle database errors without exposing "
            "SQL queries or sensitive information.\n\n"

            "6. Perform security testing against "
            "authorized applications before deployment."
        )


    # ======================================================
    # XSS
    # ======================================================

    if (
        "xss" in question_lower
        or "cross site scripting" in question_lower
        or "cross-site scripting" in question_lower
    ):

        return (
            "CROSS-SITE SCRIPTING (XSS) PREVENTION\n\n"

            "Recommended controls:\n\n"

            "1. Context-aware output encoding.\n"

            "2. Validate and sanitize untrusted input.\n"

            "3. Use framework-provided escaping mechanisms.\n"

            "4. Implement an appropriate Content Security Policy.\n"

            "5. Use HttpOnly and Secure cookie attributes "
            "where appropriate.\n\n"

            "6. Test reflected, stored and DOM-based XSS "
            "in authorized environments."
        )


    # ======================================================
    # Phishing
    # ======================================================

    if "phishing" in question_lower:

        return (
            "PHISHING RISK REDUCTION\n\n"

            "Recommended controls:\n\n"

            "1. Enable multi-factor authentication.\n"

            "2. Train users to identify suspicious messages.\n"

            "3. Use email filtering and anti-phishing controls.\n"

            "4. Verify unexpected links and attachments.\n"

            "5. Report suspicious messages to the security team.\n"

            "6. Monitor authentication logs for unusual activity."
        )


    # ======================================================
    # CVE / CVSS
    # ======================================================

    if (
        "cve" in question_lower
        or "cvss" in question_lower
        or "vulnerability" in question_lower
    ):

        return (
            "VULNERABILITY MANAGEMENT\n\n"

            "ECDP can prioritize vulnerabilities using "
            "severity, affected assets and available "
            "security findings.\n\n"

            "Recommended approach:\n\n"

            "1. Identify affected assets.\n"
            "2. Review CVE information.\n"
            "3. Check CVSS severity.\n"
            "4. Determine whether the asset is exposed.\n"
            "5. Apply the vendor security update or mitigation.\n"
            "6. Rescan the asset to verify remediation."
        )


    # ======================================================
    # General Cybersecurity
    # ======================================================

    if (
        "cybersecurity" in question_lower
        or "cyber security" in question_lower
        or "security" in question_lower
    ):

        return (
            "CYBERSECURITY GUIDANCE\n\n"

            "The ECDP Security Assistant can help analyze "
            "assets, vulnerability scans, incidents and "
            "remediation status.\n\n"

            f"Current security score: {score}/100\n"

            f"High/Critical-risk assets: "
            f"{context['assets']['high_risk']}\n"

            f"Open incidents: "
            f"{context['incidents']['open']}\n\n"

            "For application security, prioritize secure "
            "coding, strong authentication, authorization, "
            "input validation, logging, monitoring and "
            "regular vulnerability assessment."
        )


    # ======================================================
    # Default Response
    # ======================================================

    return (
        "I can help you analyze your ECDP security "
        "environment.\n\n"

        "Try asking:\n"

        "• What are my highest security risks?\n"
        "• Why is my security score low?\n"
        "• How many open incidents do I have?\n"
        "• What should I fix first?\n"
        "• What is my asset status?\n"
        "• How many vulnerability scans were completed?\n"
        "• How can I prevent SQL injection?\n"
        "• How can I prevent XSS?\n"
        "• Explain CVE and CVSS."
    )


# ==========================================================
# Risk Level Helper
# ==========================================================

def get_risk_level(score):

    if score >= 80:

        return "Low"

    elif score >= 60:

        return "Moderate"

    elif score >= 40:

        return "High"

    else:

        return "Critical"