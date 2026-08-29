import json

from extensions import db

from models.remediation import Remediation
from models.asset import Asset
from models.scan import Scan

from utils.audit_logger import log_action


# ==========================================================
# Generate Remediation ID
# ==========================================================

def generate_remediation_id():

    last_item = Remediation.query.order_by(
        Remediation.id.desc()
    ).first()

    if not last_item:
        next_number = 1
    else:
        next_number = last_item.id + 1

    return f"REM-{next_number:04d}"


# ==========================================================
# Normalize Severity
# ==========================================================

def normalize_severity(severity, cvss=0.0):

    severity = str(
        severity or ""
    ).strip().capitalize()

    if severity in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]:
        return severity

    try:
        cvss = float(cvss or 0.0)
    except (
        TypeError,
        ValueError
    ):
        cvss = 0.0

    if cvss >= 9.0:
        return "Critical"

    if cvss >= 7.0:
        return "High"

    if cvss >= 4.0:
        return "Medium"

    return "Low"


# ==========================================================
# Build Recommendation
# ==========================================================

def build_recommendation(cve):

    cve_id = (
        cve.get("id")
        or cve.get("cve_id")
        or cve.get("CVE")
        or "identified vulnerability"
    )

    product = (
        cve.get("detected_product")
        or "affected software"
    )

    version = (
        cve.get("detected_version")
        or ""
    )

    severity = normalize_severity(
        cve.get("severity"),
        cve.get("score")
    )

    recommendation = (
        f"Investigate and remediate {cve_id}. "
        f"Review the affected {product}"
    )

    if version:
        recommendation += (
            f" version {version}"
        )

    recommendation += (
        f". Apply the vendor-recommended security "
        f"update or patch, verify that the vulnerable "
        f"service is no longer exposed, and perform a "
        f"follow-up vulnerability scan."
    )

    if severity in [
        "Critical",
        "High"
    ]:
        recommendation += (
            " Because this finding is high priority, "
            "address it as soon as possible."
        )

    return recommendation


# ==========================================================
# Create Remediation For CVE
# ==========================================================

def create_cve_remediation(
    cve,
    scan,
    asset=None
):

    if not isinstance(
        cve,
        dict
    ):
        return None

    # ------------------------------------------------------
    # CVE ID
    # ------------------------------------------------------

    cve_id = (
        cve.get("id")
        or cve.get("cve_id")
        or cve.get("CVE")
        or cve.get("cve")
    )

    if not cve_id:
        return None

    cve_id = str(
        cve_id
    ).strip().upper()

    # ------------------------------------------------------
    # Prevent Duplicate Remediation
    # ------------------------------------------------------

    existing = Remediation.query.filter_by(
        cve_id=cve_id,
        scan_id=scan.id
    ).first()

    if existing:

        print(
            f"[REMEDIATION] Already exists: "
            f"{existing.remediation_id} "
            f"for {cve_id}"
        )

        return existing

    # ------------------------------------------------------
    # CVSS
    # ------------------------------------------------------

    try:

        cvss = float(
            cve.get("score")
            or cve.get("cvss")
            or 0.0
        )

    except (
        TypeError,
        ValueError
    ):

        cvss = 0.0

    # ------------------------------------------------------
    # Severity
    # ------------------------------------------------------

    severity = normalize_severity(
        cve.get("severity"),
        cvss
    )

    # ------------------------------------------------------
    # Description
    # ------------------------------------------------------

    description = (
        cve.get("description")
        or cve.get("summary")
        or "No vulnerability description available."
    )

    # ------------------------------------------------------
    # Product
    # ------------------------------------------------------

    product = (
        cve.get("detected_product")
        or "Affected service"
    )

    version = (
        cve.get("detected_version")
        or ""
    )

    port = (
        cve.get("detected_port")
        or ""
    )

    # ------------------------------------------------------
    # Title
    # ------------------------------------------------------

    title = (
        f"Remediate {cve_id}"
    )

    if product:

        title += (
            f" - {product}"
        )

    # ------------------------------------------------------
    # Recommendation
    # ------------------------------------------------------

    recommendation = build_recommendation(
        cve
    )

    # ------------------------------------------------------
    # Create Remediation
    # ------------------------------------------------------

    item = Remediation(

        remediation_id=generate_remediation_id(),

        title=title,

        cve_id=cve_id,

        asset_id=(
            asset.id
            if asset
            else scan.asset_id
        ),

        scan_id=scan.id,

        severity=severity,

        description=str(
            description
        ),

        recommendation=recommendation,

        status="Open"

    )

    # ------------------------------------------------------
    # Initial Notes
    # ------------------------------------------------------

    notes = [
        f"Automatically generated from scan {scan.id}.",
        f"Target: {scan.target}."
    ]

    if product:

        notes.append(
            f"Detected product: {product}."
        )

    if version:

        notes.append(
            f"Detected version: {version}."
        )

    if port:

        notes.append(
            f"Detected port: {port}."
        )

    notes.append(
        f"CVSS score: {cvss:.1f}."
    )

    item.notes = "\n".join(
        notes
    )

    # ------------------------------------------------------
    # Save
    # ------------------------------------------------------

    db.session.add(
        item
    )

    db.session.flush()

    print(
        f"[REMEDIATION] Created "
        f"{item.remediation_id} "
        f"for {cve_id}"
    )

    # ------------------------------------------------------
    # Audit
    # ------------------------------------------------------

    log_action(
        "REMEDIATION_AUTO_CREATED",
        (
            f"Automatic remediation created. "
            f"Remediation: {item.remediation_id}. "
            f"CVE: {cve_id}. "
            f"Scan: {scan.id}. "
            f"Target: {scan.target}. "
            f"Severity: {severity}."
        )
    )

    return item


# ==========================================================
# Create Remediations From Scan
# ==========================================================

def create_remediations_from_scan(
    scan,
    asset=None
):

    if scan is None:
        return []

    # ------------------------------------------------------
    # Load vulnerabilities
    # ------------------------------------------------------

    vulnerabilities = scan.vulnerabilities

    if not vulnerabilities:
        print(
            f"[REMEDIATION] Scan {scan.id} "
            f"contains no vulnerabilities."
        )

        return []

    # ------------------------------------------------------
    # Parse JSON
    # ------------------------------------------------------

    if isinstance(
        vulnerabilities,
        str
    ):

        try:

            vulnerabilities = json.loads(
                vulnerabilities
            )

        except (
            TypeError,
            ValueError
        ):

            print(
                f"[REMEDIATION] Invalid vulnerability "
                f"JSON for scan {scan.id}."
            )

            return []

    # ------------------------------------------------------
    # Ensure List
    # ------------------------------------------------------

    if not isinstance(
        vulnerabilities,
        list
    ):

        return []

    # ------------------------------------------------------
    # Create Remediations
    # ------------------------------------------------------

    created = []

    for cve in vulnerabilities:

        item = create_cve_remediation(
            cve=cve,
            scan=scan,
            asset=asset
        )

        if item:

            created.append(
                item
            )

    print(
        f"[REMEDIATION] Scan {scan.id}: "
        f"{len(created)} remediation record(s) "
        f"created/found."
    )

    return created