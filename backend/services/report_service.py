from models.asset import Asset
from models.scan import Scan
from models.incident import Incident
from models.remediation import Remediation

import ast
import json


# ==========================================================
# Vulnerability Extraction Helpers
# ==========================================================

def _parse_vulnerability_data(value):
    """Safely convert stored vulnerability data into a Python list."""

    if not value:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        return [value]

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []

        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

        try:
            parsed = ast.literal_eval(value)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except (ValueError, SyntaxError):
            pass

    return []


def _normalize_vulnerability(vulnerability, scan, asset=None):
    """Normalize a stored vulnerability into a report-friendly dictionary."""

    if not isinstance(vulnerability, dict):
        return None

    cve_id = (
        vulnerability.get("id")
        or vulnerability.get("cve_id")
        or vulnerability.get("CVE")
        or vulnerability.get("cve")
    )

    if not cve_id:
        return None

    cve_id = str(cve_id).strip().upper()

    try:
        cvss = float(
            vulnerability.get("score")
            if vulnerability.get("score") is not None
            else vulnerability.get("cvss", 0)
        )
    except (TypeError, ValueError):
        cvss = 0.0

    cvss = max(0.0, min(10.0, cvss))

    severity = (
        vulnerability.get("severity")
        or vulnerability.get("baseSeverity")
        or vulnerability.get("severity_rating")
    )

    if severity:
        severity = str(severity).strip().upper()
    elif cvss >= 9.0:
        severity = "CRITICAL"
    elif cvss >= 7.0:
        severity = "HIGH"
    elif cvss >= 4.0:
        severity = "MEDIUM"
    elif cvss > 0:
        severity = "LOW"
    else:
        severity = "UNKNOWN"

    return {
        "id": cve_id,
        "description": str(
            vulnerability.get("description")
            or vulnerability.get("summary")
            or "No description available."
        ),
        "score": cvss,
        "severity": severity,
        "cwe": str(
            vulnerability.get("cwe")
            or vulnerability.get("cwe_id")
            or "N/A"
        ),
        "reference": (
            vulnerability.get("reference")
            or vulnerability.get("nvd_url")
            or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        ),
        "published": (
            vulnerability.get("published")
            or vulnerability.get("published_date")
            or vulnerability.get("publishedDate")
            or ""
        ),
        "detected_product": vulnerability.get("detected_product") or "N/A",
        "detected_version": vulnerability.get("detected_version") or "N/A",
        "detected_port": vulnerability.get("detected_port") or "N/A",
        "target": getattr(scan, "target", None) or "N/A",
        "scan_date": (
            scan.scan_date.strftime("%Y-%m-%d %H:%M")
            if getattr(scan, "scan_date", None)
            else "N/A"
        ),
        "asset_name": (
            getattr(asset, "asset_name", None)
            if asset is not None
            else None
        ) or "N/A",
    }


def generate_vulnerability_summary():
    """Extract and summarize CVE findings stored in completed scans."""

    completed_scans = Scan.query.filter_by(
        status="Completed"
    ).order_by(
        Scan.scan_date.desc()
    ).all()

    findings = []
    unique_cves = set()
    seen_findings = set()

    critical = 0
    high = 0
    medium = 0
    low = 0
    highest_cvss = 0.0

    for scan in completed_scans:
        asset = None
        asset_id = getattr(scan, "asset_id", None)

        if asset_id:
            try:
                asset = Asset.query.get(asset_id)
            except Exception:
                asset = None

        vulnerabilities = _parse_vulnerability_data(
            getattr(scan, "vulnerabilities", None)
        )

        for vulnerability in vulnerabilities:
            finding = _normalize_vulnerability(
                vulnerability,
                scan,
                asset
            )

            if not finding:
                continue

            unique_cves.add(finding["id"])
            highest_cvss = max(
                highest_cvss,
                finding["score"]
            )

            severity = finding["severity"]

            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1
            elif severity == "MEDIUM":
                medium += 1
            elif severity == "LOW":
                low += 1

            finding_key = (
                finding["id"],
                finding["target"],
                str(finding["detected_port"]),
            )

            if finding_key in seen_findings:
                continue

            seen_findings.add(finding_key)
            findings.append(finding)

    findings.sort(
        key=lambda item: (
            item.get("score", 0),
            item.get("severity", "")
        ),
        reverse=True
    )

    return {
        "total_findings": len(findings),
        "unique_cve_count": len(unique_cves),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "highest_cvss": round(highest_cvss, 1),
        "findings": findings,
    }


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
    # Remediation Statistics
    # ======================================================

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

    closed_remediations = Remediation.query.filter_by(
        status="Closed"
    ).count()

    critical_remediations = Remediation.query.filter_by(
        severity="Critical"
    ).count()

    high_remediations = Remediation.query.filter_by(
        severity="High"
    ).count()

    medium_remediations = Remediation.query.filter_by(
        severity="Medium"
    ).count()

    low_remediations = Remediation.query.filter_by(
        severity="Low"
    ).count()

    recent_remediations = Remediation.query.order_by(
        Remediation.created_at.desc()
    ).limit(5).all()


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
    # Vulnerability Findings
    # ======================================================

    vulnerability_summary = generate_vulnerability_summary()


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

        "vulnerabilities": vulnerability_summary,

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

        "remediations": {
            "total": total_remediations,
            "open": open_remediations,
            "in_progress": in_progress_remediations,
            "resolved": resolved_remediations,
            "verified": verified_remediations,
            "closed": closed_remediations,
            "critical": critical_remediations,
            "high": high_remediations,
            "medium": medium_remediations,
            "low": low_remediations,
            "recent": recent_remediations
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

def _normalize_text(value):
    """Normalize text for safe asset/incident correlation."""

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


def _asset_matches_incident(asset, incident):
    """Return True when an incident can reasonably be linked to an asset."""

    asset_name = _normalize_text(
        getattr(asset, "asset_name", None)
    )
    asset_ip = _normalize_text(
        getattr(asset, "ip_address", None)
    )

    incident_asset = _normalize_text(
        getattr(incident, "asset", None)
    )
    incident_title = _normalize_text(
        getattr(incident, "title", None)
    )
    incident_description = _normalize_text(
        getattr(incident, "description", None)
    )

    incident_text = " ".join([
        incident_asset,
        incident_title,
        incident_description
    ])

    incident_text_compact = incident_text.replace(" ", "")
    asset_name_compact = asset_name.replace(" ", "")
    asset_ip_compact = asset_ip.replace(" ", "")

    if asset_name and (
        asset_name in incident_asset
        or incident_asset in asset_name
        or asset_name_compact in incident_text_compact
    ):
        return True

    if asset_ip and (
        asset_ip in incident_text
        or asset_ip_compact in incident_text_compact
    ):
        return True

    if asset_name and (
        asset_name in incident_title
        or asset_name in incident_description
    ):
        return True

    if asset_ip and (
        asset_ip in incident_title
        or asset_ip in incident_description
    ):
        return True

    return False


def _get_related_scans(asset):
    """Return scans related to an asset by ID, with target-IP fallback."""

    related_scans = Scan.query.filter_by(
        asset_id=asset.id
    ).order_by(
        Scan.scan_date.desc()
    ).all()

    if not related_scans and getattr(asset, "ip_address", None):
        related_scans = Scan.query.filter_by(
            target=asset.ip_address
        ).order_by(
            Scan.scan_date.desc()
        ).all()

    return related_scans


def _calculate_open_ports(scans):
    """Count distinct open ports across correlated scans."""

    ports_found = set()

    for scan in scans:
        ports = getattr(scan, "open_ports", None) or ""

        if not ports or ports.strip().lower() == "none":
            continue

        for port in ports.split(","):
            port = port.strip()
            if port:
                ports_found.add(port)

    return len(ports_found)


def generate_soc_correlation():
    """
    Correlate all High/Critical assets with vulnerability scans and
    security incidents, then select the asset with the strongest
    available security evidence.
    """

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(["High", "Critical"])
    ).order_by(
        Asset.id.asc()
    ).all()

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
                "No high or critical-risk asset is currently "
                "available for SOC correlation."
            ),
            "response": (
                "Continue regular security monitoring "
                "and vulnerability assessment."
            ),
            "scans": [],
            "incidents": []
        }

    all_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    candidates = []

    for asset in high_risk_assets:
        related_scans = _get_related_scans(asset)

        related_incidents = [
            incident
            for incident in all_incidents
            if _asset_matches_incident(asset, incident)
        ]

        # Evidence-based score used only to select the most useful
        # asset for the single SOC correlation panel.
        evidence_score = (
            len(related_incidents) * 10
            + len(related_scans) * 3
        )

        if getattr(asset, "risk_level", "") == "Critical":
            evidence_score += 100
        elif getattr(asset, "risk_level", "") == "High":
            evidence_score += 50

        open_incident_count = sum(
            1
            for incident in related_incidents
            if (getattr(incident, "status", "") or "")
            .strip()
            .lower() == "open"
        )

        evidence_score += open_incident_count * 5

        candidates.append({
            "asset": asset,
            "scans": related_scans,
            "incidents": related_incidents,
            "score": evidence_score
        })

    selected = max(
        candidates,
        key=lambda item: item["score"]
    )

    high_risk_asset = selected["asset"]
    related_scans = selected["scans"]
    related_incidents = selected["incidents"]

    open_ports = _calculate_open_ports(
        related_scans
    )

    priority = "MEDIUM"

    if high_risk_asset.risk_level == "Critical":
        priority = "CRITICAL"

    elif any(
        (incident.severity or "").strip().lower() == "critical"
        for incident in related_incidents
    ):
        priority = "CRITICAL"

    elif (
        high_risk_asset.risk_level == "High"
        and any(
            (incident.status or "").strip().lower() == "open"
            for incident in related_incidents
        )
    ):
        priority = "HIGH"

    elif high_risk_asset.risk_level == "High":
        priority = "HIGH"

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

    if related_incidents:
        finding = (
            f"The asset {high_risk_asset.asset_name} "
            f"is classified as {high_risk_asset.risk_level} "
            f"risk and has {len(related_incidents)} "
            f"related security incident(s). The highest "
            f"incident severity is {highest_severity.capitalize()}."
        )

    elif related_scans:
        finding = (
            f"The asset {high_risk_asset.asset_name} "
            f"is classified as {high_risk_asset.risk_level} "
            f"risk and has {len(related_scans)} "
            f"associated vulnerability scan(s)."
        )

    else:
        finding = (
            f"The asset {high_risk_asset.asset_name} "
            f"is classified as {high_risk_asset.risk_level} "
            f"risk but has no associated scan or incident records."
        )

    if priority == "CRITICAL":
        response = (
            "Immediately investigate the correlated critical "
            "security condition. Validate the affected asset, "
            "investigate the associated incident, contain the "
            "threat if necessary, and begin remediation."
        )

    elif priority == "HIGH":
        response = (
            "Investigate the associated high-severity or open "
            "incident, validate the affected asset, review "
            "vulnerability scan results, and prioritize remediation."
        )

    elif priority == "MEDIUM":
        response = (
            "Review the asset and its associated security activity. "
            "Perform vulnerability assessment and address identified "
            "security weaknesses."
        )

    else:
        response = (
            "Continue regular security monitoring and periodic "
            "vulnerability assessment."
        )

    return {
        "available": True,
        "asset_name": high_risk_asset.asset_name,
        "ip_address": high_risk_asset.ip_address,
        "asset_risk": high_risk_asset.risk_level,
        "asset_status": high_risk_asset.status,
        "related_scans": len(related_scans),
        "related_incidents": len(related_incidents),
        "open_ports": open_ports,
        "priority": priority,
        "finding": finding,
        "response": response,
        "scans": related_scans,
        "incidents": related_incidents
    }
