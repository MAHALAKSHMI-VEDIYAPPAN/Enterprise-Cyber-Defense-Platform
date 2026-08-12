from models.asset import Asset
from models.scan import Scan
from models.incident import Incident


def generate_security_analysis():
    """
    Analyze current ECDP security data and generate
    security recommendations.
    """

    # ======================================================
    # Collect Database Information
    # ======================================================

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

    # ======================================================
    # Calculate Security Score
    # ======================================================

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

    score = max(
        0,
        min(
            100,
            round(score)
        )
    )

    # ======================================================
    # Determine Risk Level
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
    # Generate Recommendations
    # ======================================================

    recommendations = []

    if high_risk_assets > 0:

        recommendations.append(
            "Prioritize remediation of high or critical-risk assets."
        )

    if open_incidents > 0:

        recommendations.append(
            "Investigate and resolve all open security incidents."
        )

    if critical_incidents > 0:

        recommendations.append(
            "Immediately investigate critical security incidents."
        )

    if failed_scans > 0:

        recommendations.append(
            "Investigate failed vulnerability scans."
        )

    if total_scans == 0:

        recommendations.append(
            "Perform a vulnerability scan on registered assets."
        )

    if not recommendations:

        recommendations.append(
            "Continue regular vulnerability scanning and "
            "security monitoring."
        )

    # ======================================================
    # Security Summary
    # ======================================================

    if risk_level == "Low":

        summary = (
            "The current security posture is healthy. "
            "Continue regular monitoring and vulnerability scanning."
        )

    elif risk_level == "Moderate":

        summary = (
            "The environment has some security concerns that "
            "should be reviewed and addressed."
        )

    elif risk_level == "High":

        summary = (
            "The environment has significant security risks. "
            "Immediate remediation and monitoring are recommended."
        )

    else:

        summary = (
            "The environment is in a critical security state. "
            "Immediate investigation and remediation are required."
        )

    # ======================================================
    # Return Analysis
    # ======================================================

    return {

        "score": score,

        "risk_level": risk_level,

        "summary": summary,

        "statistics": {

            "total_assets": total_assets,
            "active_assets": active_assets,
            "high_risk_assets": high_risk_assets,

            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,

            "total_incidents": total_incidents,
            "open_incidents": open_incidents,

            "critical_incidents": critical_incidents,
            "high_incidents": high_incidents,
            "medium_incidents": medium_incidents,
            "low_incidents": low_incidents
        },

        "recommendations": recommendations
    }