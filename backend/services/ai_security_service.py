from models.asset import Asset
from models.scan import Scan
from models.incident import Incident
from models.remediation import Remediation


# ==========================================================
# ECDP SECURITY DATA
# ==========================================================

def get_ecdp_context():

    total_assets = Asset.query.count()

    active_assets = Asset.query.filter_by(
        status="Active"
    ).count()

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(["High", "Critical"])
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
# SECURITY SCORE
# ==========================================================

def calculate_security_score(context):

    total_assets = context["assets"]["total"]
    high_risk_assets = context["assets"]["high_risk"]
    open_incidents = context["incidents"]["open"]
    critical_incidents = context["incidents"]["critical"]

    score = 100

    if total_assets > 0:

        risk_percentage = (
            high_risk_assets / total_assets
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
# RISK LEVEL
# ==========================================================

def get_risk_level(score):

    if score >= 80:
        return "Low"

    elif score >= 60:
        return "Moderate"

    elif score >= 40:
        return "High"

    return "Critical"


# ==========================================================
# REQUIRED BY ai_security.py
# ==========================================================

def generate_security_analysis():

    context = get_ecdp_context()

    score = calculate_security_score(
        context
    )

    risk_level = get_risk_level(
        score
    )

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

    if risk_level == "Low":

        summary = (
            "The current security posture is healthy. "
            "Continue regular monitoring and "
            "vulnerability scanning."
        )

    elif risk_level == "Moderate":

        summary = (
            "The environment has some security concerns "
            "that should be reviewed and addressed."
        )

    elif risk_level == "High":

        summary = (
            "The environment has significant security "
            "risks. Immediate remediation and "
            "monitoring are recommended."
        )

    else:

        summary = (
            "The environment is in a critical security "
            "state. Immediate investigation and "
            "remediation are required."
        )

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
# AI SECURITY ASSISTANT
# ==========================================================

def ask_security_ai(question):

    if not question:

        return "Please enter a cybersecurity question."

    question = question.strip()

    q = question.lower()


    # ======================================================
    # GREETINGS
    # ======================================================

    if q in {
        "hi",
        "hello",
        "hey",
        "hii",
        "hiii",
        "good morning",
        "good afternoon",
        "good evening"
    }:

        return (
            "Hello! 👋 I'm your ECDP Security Assistant.\n\n"
            "I can help you understand your security "
            "environment and answer cybersecurity questions.\n\n"
            "What would you like to investigate?"
        )


    # ======================================================
    # HOW ARE YOU
    # ======================================================

    if (
        "how are you" in q
        or "how r u" in q
        or "how are u" in q
    ):

        return (
            "I'm doing great! 😊\n\n"
            "I'm ready to help you with cybersecurity "
            "questions or analyze your ECDP environment."
        )


    # ======================================================
    # THANK YOU
    # ======================================================

    if (
        "thank you" in q
        or "thanks" in q
        or "thank u" in q
    ):

        return (
            "You're welcome! 😊\n\n"
            "Let me know if you need any more "
            "security analysis."
        )


    # ======================================================
    # GOODBYE
    # ======================================================

    if q in {
        "bye",
        "goodbye",
        "see you",
        "see you later"
    }:

        return (
            "Goodbye! 👋\n\n"
            "Stay secure and keep monitoring "
            "your ECDP environment."
        )


    # ======================================================
    # IDENTITY
    # ======================================================

    if (
        "who are you" in q
        or "what are you" in q
    ):

        return (
            "I'm the ECDP Security Assistant. 🤖\n\n"
            "I provide cybersecurity guidance and "
            "analyze security information available "
            "in your Enterprise Cyber Defense Platform."
        )


    # ======================================================
    # GET DATABASE CONTEXT
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
            "I couldn't access the current "
            "ECDP security data."
        )


    # ======================================================
    # SECURITY SUMMARY
    # ======================================================

    if any(x in q for x in [
        "security summary",
        "overall security",
        "overall status",
        "security overview",
        "summarize my security",
        "give me a summary"
    ]):

        return (
            "ECDP SECURITY SUMMARY\n\n"

            f"Security Score: {score}/100\n"
            f"Risk Level: {get_risk_level(score)}\n\n"

            f"Total Assets: "
            f"{context['assets']['total']}\n"

            f"Active Assets: "
            f"{context['assets']['active']}\n"

            f"High/Critical-Risk Assets: "
            f"{context['assets']['high_risk']}\n\n"

            f"Total Incidents: "
            f"{context['incidents']['total']}\n"

            f"Open Incidents: "
            f"{context['incidents']['open']}\n"

            f"Critical Incidents: "
            f"{context['incidents']['critical']}\n"

            f"High Incidents: "
            f"{context['incidents']['high']}\n\n"

            f"Total Scans: "
            f"{context['scans']['total']}\n"

            f"Completed Scans: "
            f"{context['scans']['completed']}\n"

            f"Failed Scans: "
            f"{context['scans']['failed']}\n\n"

            f"Open Remediations: "
            f"{context['remediations']['open']}\n\n"

            "Recommended priority:\n"

            "1. Address Critical and High security issues.\n"
            "2. Review high-risk assets.\n"
            "3. Resolve open remediation tasks.\n"
            "4. Investigate failed vulnerability scans."
        )


    # ======================================================
    # SECURITY SCORE
    # ======================================================

    if (
        "security score" in q
        or "security rating" in q
        or q == "score"
        or "how secure am i" in q
        or "why is my score low" in q
    ):

        return (
            "CURRENT SECURITY SCORE\n\n"

            f"Security Score: {score}/100\n\n"

            f"Risk Level: "
            f"{get_risk_level(score)}\n\n"

            "The score is calculated from the "
            "current security posture recorded in ECDP."
        )


    # ======================================================
    # RISKY ASSETS
    # ======================================================

    if (
        "security risks" in q
        or "risky assets" in q
        or "risky asset" in q
        or "high risk assets" in q
        or "high-risk assets" in q
        or "critical assets" in q
        or "assets at risk" in q
        or "which assets are risky" in q
    ):

        return (
            "HIGHEST CURRENT SECURITY RISKS\n\n"

            f"High/Critical-risk assets: "
            f"{context['assets']['high_risk']}\n"

            f"Open incidents: "
            f"{context['incidents']['open']}\n"

            f"Critical incidents: "
            f"{context['incidents']['critical']}\n"

            f"High incidents: "
            f"{context['incidents']['high']}\n\n"

            "Recommended action:\n\n"

            "1. Investigate Critical and High incidents.\n"
            "2. Review High/Critical-risk assets.\n"
            "3. Complete pending remediation tasks.\n"
            "4. Investigate failed vulnerability scans."
        )


    # ======================================================
    # INCIDENTS
    # ======================================================

    if (
        "open incidents" in q
        or "incident status" in q
        or "incident count" in q
        or "how many incidents" in q
        or "any incidents" in q
        or "incidents should i worry about" in q
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
    # ASSETS
    # ======================================================

    if (
        "asset status" in q
        or "asset count" in q
        or "how many assets" in q
        or "show my assets" in q
        or "show me my assets" in q
        or "tell me about my assets" in q
        or q == "assets"
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
    # SCANS
    # ======================================================

    if (
        "scan" in q
        or "scans" in q
        or "vulnerability scan" in q
        or "are my scans okay" in q
        or "scan status" in q
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
            "ensure that assets are properly assessed."
        )


    # ======================================================
    # REMEDIATION
    # ======================================================

    if (
        "remediation" in q
        or "remediations" in q
        or "fix first" in q
        or "what should i fix" in q
        or "what needs fixing" in q
        or "what needs to be fixed" in q
        or "priority fixes" in q
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

            "Recommended priority:\n\n"

            "1. Critical security issues\n"
            "2. High severity issues\n"
            "3. Internet-facing vulnerabilities\n"
            "4. Medium-risk issues\n"
            "5. Low-risk findings"
        )


    # ======================================================
    # SQL INJECTION
    # ======================================================

    if (
        "sql injection" in q
        or "sqli" in q
        or "sql attack" in q
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
        "xss" in q
        or "cross site scripting" in q
        or "cross-site scripting" in q
    ):

        return (
            "CROSS-SITE SCRIPTING (XSS) PREVENTION\n\n"

            "Recommended controls:\n\n"

            "1. Use context-aware output encoding.\n\n"

            "2. Validate and sanitize untrusted input.\n\n"

            "3. Use framework-provided escaping mechanisms.\n\n"

            "4. Implement an appropriate Content Security Policy.\n\n"

            "5. Use HttpOnly and Secure cookie attributes "
            "where appropriate.\n\n"

            "6. Test reflected, stored and DOM-based XSS "
            "in authorized environments."
        )


    # ======================================================
    # PHISHING
    # ======================================================

    if "phishing" in q:

        return (
            "PHISHING RISK REDUCTION\n\n"

            "Recommended controls:\n\n"

            "1. Enable multi-factor authentication.\n\n"

            "2. Train users to identify suspicious messages.\n\n"

            "3. Use email filtering and anti-phishing controls.\n\n"

            "4. Verify unexpected links and attachments.\n\n"

            "5. Report suspicious messages to the security team.\n\n"

            "6. Monitor authentication logs for unusual activity."
        )


    # ======================================================
    # CVE / CVSS / VULNERABILITIES
    # ======================================================

    if (
        "cve" in q
        or "cvss" in q
        or "vulnerabilit" in q
    ):

        return (
            "VULNERABILITY MANAGEMENT\n\n"

            "ECDP can help prioritize vulnerabilities "
            "using severity, affected assets and "
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
    # NETWORK SECURITY
    # ======================================================

    if (
        "network security" in q
        or "secure network" in q
        or "network attack" in q
        or "network risk" in q
    ):

        return (
            "NETWORK SECURITY\n\n"

            "Important controls include:\n\n"

            "1. Use firewalls and network segmentation.\n"
            "2. Disable unnecessary services and ports.\n"
            "3. Apply security updates regularly.\n"
            "4. Monitor network traffic and authentication logs.\n"
            "5. Use strong authentication and access controls.\n"
            "6. Regularly scan authorized systems for vulnerabilities."
        )


    # ======================================================
    # GENERAL CYBERSECURITY
    # ======================================================

    if (
        "cybersecurity" in q
        or "cyber security" in q
    ):

        return (
            "CYBERSECURITY GUIDANCE\n\n"

            "I can help with application security, "
            "network security, vulnerability management, "
            "incident response and your ECDP environment.\n\n"

            f"Current security score: {score}/100\n"

            f"High/Critical-risk assets: "
            f"{context['assets']['high_risk']}\n"

            f"Open incidents: "
            f"{context['incidents']['open']}\n\n"

            "Tell me what security topic or ECDP "
            "information you want to investigate."
        )


    # ======================================================
    # DEFAULT
    # ======================================================

    return (
        "I'm not sure how to answer that yet. 😊\n\n"

        "I can help with cybersecurity topics and "
        "your ECDP environment.\n\n"

        "Try asking:\n"

        "• Give me a security summary\n"
        "• Show me my risky assets\n"
        "• Any incidents I should worry about?\n"
        "• Are my scans okay?\n"
        "• What should I fix first?\n"
        "• How can I prevent SQL injection?\n"
        "• How can I prevent XSS?\n"
        "• Explain CVE and CVSS."
    )