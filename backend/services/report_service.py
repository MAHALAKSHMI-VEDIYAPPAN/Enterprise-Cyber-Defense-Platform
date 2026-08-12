from models.asset import Asset
from models.scan import Scan
from models.incident import Incident


# ==========================================================
# Generate Complete Security Report
# ==========================================================

def generate_security_report():
    """
    Collect security information from the ECDP database
    and return it as a structured dictionary.
    """

    # ======================================================
    # Asset Statistics
    # ======================================================

    total_assets = Asset.query.count()

    active_assets = Asset.query.filter_by(
        status="Active"
    ).count()

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(["High", "Critical"])
    ).count()


    # ======================================================
    # Scan Statistics
    # ======================================================

    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(
        status="Completed"
    ).count()

    failed_scans = Scan.query.filter(
        Scan.status != "Completed"
    ).count()


    # ======================================================
    # Incident Statistics
    # ======================================================

    total_incidents = Incident.query.count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    in_progress_incidents = Incident.query.filter_by(
        status="In Progress"
    ).count()

    resolved_incidents = Incident.query.filter_by(
        status="Resolved"
    ).count()

    closed_incidents = Incident.query.filter_by(
        status="Closed"
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
    # Recent Incidents
    # ======================================================

    recent_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).limit(5).all()


    # ======================================================
    # Recent Scans
    # ======================================================

    recent_scans = Scan.query.order_by(
        Scan.scan_date.desc()
    ).limit(5).all()


    # ======================================================
    # Security Score
    # ======================================================

    security_score = calculate_security_score(
        total_assets=total_assets,
        high_risk_assets=high_risk_assets,
        total_incidents=total_incidents,
        critical_incidents=critical_incidents,
        open_incidents=open_incidents
    )


    # ======================================================
    # SOC Correlation
    # ======================================================

    correlation = generate_soc_correlation()


    # ======================================================
    # Final Report
    # ======================================================

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
            "in_progress": in_progress_incidents,
            "resolved": resolved_incidents,
            "closed": closed_incidents,
            "critical": critical_incidents,
            "high": high_incidents,
            "medium": medium_incidents,
            "low": low_incidents
        },

        "recent_incidents": recent_incidents,

        "recent_scans": recent_scans,

        "security_score": security_score,

        "correlation": correlation
    }


# ==========================================================
# Security Score
# ==========================================================

def calculate_security_score(
    total_assets,
    high_risk_assets,
    total_incidents,
    critical_incidents,
    open_incidents
):
    """
    Calculate an application-level security posture score.

    This is not an industry-standard risk score.
    """

    score = 100


    # ======================================================
    # High/Critical Asset Penalty
    # ======================================================

    if total_assets > 0:

        risk_percentage = (
            high_risk_assets / total_assets
        ) * 100

        score -= min(
            risk_percentage * 0.30,
            30
        )


    # ======================================================
    # Critical Incident Penalty
    # ======================================================

    score -= min(
        critical_incidents * 10,
        30
    )


    # ======================================================
    # Open Incident Penalty
    # ======================================================

    score -= min(
        open_incidents * 3,
        20
    )


    # ======================================================
    # Keep Score Between 0 and 100
    # ======================================================

    score = max(
        0,
        min(
            100,
            round(score)
        )
    )


    return score


# ==========================================================
# SOC Correlation
# ==========================================================

def generate_soc_correlation():
    """
    Correlate high/critical-risk assets with vulnerability
    scans and security incidents.
    """

    # ======================================================
    # Find High/Critical Risk Assets
    # ======================================================

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(["High", "Critical"])
    ).order_by(
        Asset.id.asc()
    ).all()


    # ======================================================
    # No High-Risk Asset
    # ======================================================

    if not high_risk_assets:

        return {

            "available": False,

            "asset_name": "N/A",

            "ip_address": "N/A",

            "asset_risk": "N/A",

            "asset_status": "N/A",

            "related_scans": 0,

            "related_incidents": 0,

            "open_ports": 0,

            "priority": "LOW",

            "finding": (
                "No high or critical-risk asset is "
                "currently available for SOC correlation."
            ),

            "response": (
                "Continue regular security monitoring "
                "and vulnerability assessment."
            ),

            "scans": [],

            "incidents": []
        }


    # ======================================================
    # Select High-Risk Asset
    # ======================================================

    high_risk_asset = high_risk_assets[0]


    # ======================================================
    # Find Related Scans
    # ======================================================

    related_scans = Scan.query.filter_by(
        asset_id=high_risk_asset.id
    ).order_by(
        Scan.scan_date.desc()
    ).all()


    # ======================================================
    # Fallback For Older Scans
    # ======================================================

    if not related_scans:

        related_scans = Scan.query.filter_by(
            target=high_risk_asset.ip_address
        ).order_by(
            Scan.scan_date.desc()
        ).all()


    # ======================================================
    # Load All Incidents
    # ======================================================

    all_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()


    related_incidents = []


    # ======================================================
    # Normalize Text
    # ======================================================

    def normalize(value):

        if not value:
            return ""

        return (
            str(value)
            .strip()
            .lower()
            .replace("_", " ")
            .replace("-", " ")
            .replace("(", " ")
            .replace(")", " ")
            .replace("/", " ")
            .replace(",", " ")
        )


    # ======================================================
    # Normalize Asset Information
    # ======================================================

    asset_name = normalize(
        high_risk_asset.asset_name
    )

    asset_ip = normalize(
        high_risk_asset.ip_address
    )


    # Remove spaces for stronger comparison

    asset_name_compact = (
        asset_name.replace(" ", "")
    )

    asset_ip_compact = (
        asset_ip.replace(" ", "")
    )


    # ======================================================
    # Incident Correlation
    # ======================================================

    for incident in all_incidents:

        incident_asset = normalize(
            incident.asset
        )

        incident_title = normalize(
            incident.title
        )

        incident_description = normalize(
            incident.description
        )


        # Combine incident information

        incident_text = " ".join(
            [
                incident_asset,
                incident_title,
                incident_description
            ]
        )


        incident_text_compact = (
            incident_text.replace(" ", "")
        )


        matched = False


        # ==================================================
        # 1. Direct Asset Name Match
        # ==================================================

        if asset_name:

            if (
                asset_name in incident_asset
                or incident_asset in asset_name
                or asset_name_compact in incident_text_compact
            ):

                matched = True


        # ==================================================
        # 2. IP Address Match
        # ==================================================

        if not matched and asset_ip:

            if (
                asset_ip in incident_text
                or asset_ip_compact in incident_text_compact
            ):

                matched = True


        # ==================================================
        # 3. Asset Name In Incident Title
        # ==================================================

        if not matched and asset_name:

            if asset_name in incident_title:

                matched = True


        # ==================================================
        # 4. Asset Name In Description
        # ==================================================

        if not matched and asset_name:

            if asset_name in incident_description:

                matched = True


        # ==================================================
        # 5. IP Address In Title
        # ==================================================

        if not matched and asset_ip:

            if asset_ip in incident_title:

                matched = True


        # ==================================================
        # 6. IP Address In Description
        # ==================================================

        if not matched and asset_ip:

            if asset_ip in incident_description:

                matched = True


        # ==================================================
        # 7. Controlled Single High-Risk Asset Fallback
        #
        # If there is only one High/Critical asset and
        # the incident is High, Critical, or Open,
        # associate it with that asset when no direct
        # relationship is available.
        # ==================================================

        if not matched:

            incident_severity = (
                incident.severity or ""
            ).strip().lower()

            incident_status = (
                incident.status or ""
            ).strip().lower()


            if (
                len(high_risk_assets) == 1
                and (
                    incident_severity == "high"
                    or incident_severity == "critical"
                    or incident_status == "open"
                )
            ):

                matched = True


        # ==================================================
        # Add Correlated Incident
        # ==================================================

        if matched:

            related_incidents.append(
                incident
            )


    # ======================================================
    # Calculate Open Ports
    # ======================================================

    open_ports = 0


    for scan in related_scans:

        ports = scan.open_ports or ""


        if (
            ports
            and ports.strip().lower() != "none"
        ):

            for port in ports.split(","):

                if port.strip():

                    open_ports += 1


    # ======================================================
    # Determine Priority
    # ======================================================

    priority = "MEDIUM"


    # Critical asset

    if high_risk_asset.risk_level == "Critical":

        priority = "CRITICAL"


    # Critical incident

    elif any(
        (incident.severity or "").strip().lower()
        == "critical"
        for incident in related_incidents
    ):

        priority = "CRITICAL"


    # High-risk asset + open incident

    elif (
        high_risk_asset.risk_level == "High"
        and any(
            (incident.status or "").strip().lower()
            == "open"
            for incident in related_incidents
        )
    ):

        priority = "HIGH"


    # High-risk asset

    elif high_risk_asset.risk_level == "High":

        priority = "HIGH"


    # ======================================================
    # Determine Highest Incident Severity
    # ======================================================

    severity_order = {

        "low": 1,

        "medium": 2,

        "high": 3,

        "critical": 4
    }


    highest_severity = "low"


    for incident in related_incidents:

        current_severity = (
            incident.severity or "Low"
        ).strip().lower()


        if severity_order.get(
            current_severity,
            0
        ) > severity_order.get(
            highest_severity,
            0
        ):

            highest_severity = current_severity


    # ======================================================
    # Generate SOC Finding
    # ======================================================

    if related_incidents:

        finding = (

            f"The asset "
            f"{high_risk_asset.asset_name} "
            f"is classified as "
            f"{high_risk_asset.risk_level} "
            f"risk and has "
            f"{len(related_incidents)} "
            f"related security incident(s). "
            f"The highest incident severity "
            f"is "
            f"{highest_severity.capitalize()}."
        )


    elif related_scans:

        finding = (

            f"The asset "
            f"{high_risk_asset.asset_name} "
            f"is classified as "
            f"{high_risk_asset.risk_level} "
            f"risk and has "
            f"{len(related_scans)} "
            f"associated vulnerability scan(s)."
        )


    else:

        finding = (

            f"The asset "
            f"{high_risk_asset.asset_name} "
            f"is classified as "
            f"{high_risk_asset.risk_level} "
            f"risk but has no associated "
            f"scan or incident records."
        )


    # ======================================================
    # Recommended SOC Response
    # ======================================================

    if priority == "CRITICAL":

        response = (

            "Immediately investigate the correlated "
            "critical security condition. Validate "
            "the affected asset, investigate the "
            "associated incident, contain the threat "
            "if necessary, and begin remediation."
        )


    elif priority == "HIGH":

        response = (

            "Investigate the associated high-severity "
            "or open incident, validate the affected "
            "asset, review vulnerability scan results, "
            "and prioritize remediation."
        )


    elif priority == "MEDIUM":

        response = (

            "Review the asset and its associated "
            "security activity. Perform vulnerability "
            "assessment and address identified "
            "security weaknesses."
        )


    else:

        response = (

            "Continue regular security monitoring "
            "and periodic vulnerability assessment."
        )


    # ======================================================
    # Final SOC Correlation Result
    # ======================================================

    return {

        "available": True,

        "asset_name": high_risk_asset.asset_name,

        "ip_address": high_risk_asset.ip_address,

        "asset_risk": high_risk_asset.risk_level,

        "asset_status": high_risk_asset.status,

        "related_scans": len(
            related_scans
        ),

        "related_incidents": len(
            related_incidents
        ),

        "open_ports": open_ports,

        "priority": priority,

        "finding": finding,

        "response": response,

        "scans": related_scans,

        "incidents": related_incidents
    }