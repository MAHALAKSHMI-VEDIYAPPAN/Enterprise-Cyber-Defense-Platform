import json

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import (
    login_required,
    current_user
)

from extensions import db

from models.scan import Scan
from models.asset import Asset

from forms.scan_form import ScanForm

from services.scanner_service import run_scan

from utils.audit_logger import log_action


# ==========================================================
# Vulnerability Scanner Blueprint
# ==========================================================

scanner_bp = Blueprint(
    "scanner",
    __name__
)


# ==========================================================
# Vulnerability Scanner
# ==========================================================

@scanner_bp.route(
    "/scanner",
    methods=["GET", "POST"]
)
@login_required
def scanner():

    form = ScanForm()


    # ======================================================
    # Load Assets
    # ======================================================

    assets = Asset.query.order_by(
        Asset.asset_name.asc()
    ).all()


    # ======================================================
    # Populate Asset Dropdown
    # ======================================================
    #
    # The asset selection is OPTIONAL.
    #
    # None represents:
    #
    #     New Target / No Asset
    #
    # ======================================================

    form.asset_id.choices = [
        (
            asset.id,
            f"{asset.asset_name} - {asset.ip_address}"
        )
        for asset in assets
    ]


    # ======================================================
    # Selected Asset
    # ======================================================

    selected_asset = None


    # ======================================================
    # Handle POST
    # ======================================================

    if request.method == "POST":

        # --------------------------------------------------
        # Get selected asset safely
        # --------------------------------------------------

        asset_id = form.asset_id.data

        if asset_id:

            selected_asset = Asset.query.get(
                asset_id
            )


            # ------------------------------------------------
            # If an asset was selected but doesn't exist
            # ------------------------------------------------

            if not selected_asset:

                flash(
                    "Selected asset was not found.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "scanner.scanner"
                    )
                )


            # ------------------------------------------------
            # Load selected asset IP
            #
            # The user can still edit the IP in the form.
            # ------------------------------------------------

            if not form.target.data:

                form.target.data = (
                    selected_asset.ip_address or ""
                ).strip()


    # ======================================================
    # Initial Page Load
    # ======================================================

    elif assets:

        # --------------------------------------------------
        # Do NOT force an asset selection.
        #
        # The first option in the UI is:
        #
        #     New Target / No Asset
        #
        # --------------------------------------------------

        selected_asset = None


    # ======================================================
    # Run Scan
    # ======================================================

    if form.validate_on_submit():

        # --------------------------------------------------
        # Role Check
        # --------------------------------------------------

        if current_user.role not in [
            "Admin",
            "Analyst"
        ]:

            flash(
                "You do not have permission to run vulnerability scans.",
                "danger"
            )

            return redirect(
                url_for(
                    "scanner.scanner"
                )
            )


        # ==================================================
        # Get Target
        # ==================================================

        target = (
            form.target.data or ""
        ).strip()


        if not target:

            flash(
                "Please provide a valid scan target.",
                "danger"
            )

            return redirect(
                url_for(
                    "scanner.scanner"
                )
            )


        # ==================================================
        # Determine Scan Mode
        # ==================================================

        asset_was_selected = (
            form.asset_id.data is not None
            and form.asset_id.data != ""
            and selected_asset is not None
        )


        if asset_was_selected:

            print(
                f"[SCANNER] Existing asset selected: "
                f"{selected_asset.asset_name}"
            )

            print(
                f"[SCANNER] Asset IP: "
                f"{selected_asset.ip_address}"
            )

            print(
                f"[SCANNER] Scan target: "
                f"{target}"
            )

        else:

            print(
                f"[SCANNER] New target scan: "
                f"{target}"
            )


        # ==================================================
        # Audit - Scan Started
        # ==================================================

        if selected_asset:

            log_action(
                "SCAN_STARTED",
                (
                    f"Vulnerability scan started for "
                    f"asset {selected_asset.asset_name}. "
                    f"Selected asset IP: "
                    f"{selected_asset.ip_address}. "
                    f"Scan target: {target}."
                )
            )

        else:

            log_action(
                "SCAN_STARTED",
                (
                    f"Vulnerability scan started for "
                    f"new authorized target {target}. "
                    f"No existing asset was selected."
                )
            )


        # ==================================================
        # Run Nmap + CVE Scan
        # ==================================================

        try:

            result = run_scan(
                target
            )

        except Exception as error:

            # ----------------------------------------------
            # Audit - Scan Failed
            # ----------------------------------------------

            log_action(
                "SCAN_FAILED",
                (
                    f"Vulnerability scan failed for "
                    f"target {target}. "
                    f"Error: {str(error)}"
                )
            )


            flash(
                f"Scan failed for {target}.",
                "danger"
            )


            return redirect(
                url_for(
                    "scanner.scanner"
                )
            )


        # ==================================================
        # Extract Scan Results
        # ==================================================

        scan_status = result.get(
            "status",
            "Failed"
        )


        open_ports = result.get(
            "open_ports",
            ""
        )


        services = result.get(
            "services",
            ""
        )


        vulnerabilities = result.get(
            "vulnerabilities",
            []
        )


        max_cvss = result.get(
            "max_cvss",
            0.0
        )


        risk_level = result.get(
            "risk_level",
            "Low"
        )


        # ==================================================
        # Normalize Vulnerabilities
        # ==================================================

        if not isinstance(
            vulnerabilities,
            list
        ):

            vulnerabilities = []


        # ==================================================
        # Normalize CVSS
        # ==================================================

        try:

            max_cvss = float(
                max_cvss or 0.0
            )

        except (
            TypeError,
            ValueError
        ):

            max_cvss = 0.0


        # --------------------------------------------------
        # Keep CVSS within valid range
        # --------------------------------------------------

        max_cvss = max(
            0.0,
            min(
                max_cvss,
                10.0
            )
        )


        # ==================================================
        # Normalize Risk
        # ==================================================

        risk_level = str(
            risk_level or "Low"
        ).strip()


        if risk_level not in [
            "Low",
            "Medium",
            "High",
            "Critical"
        ]:

            risk_level = "Low"


        # ==================================================
        # Convert Vulnerabilities to JSON
        # ==================================================

        try:

            vulnerabilities_json = json.dumps(
                vulnerabilities,
                ensure_ascii=False
            )

        except (
            TypeError,
            ValueError
        ):

            vulnerabilities_json = "[]"

            vulnerabilities = []


        # ==================================================
        # Handle New Target Asset
        # ==================================================
        #
        # If the user didn't select an asset:
        #
        # 1. Check whether the target already exists.
        #
        # 2. If it exists, associate the scan with it.
        #
        # 3. If it doesn't exist AND the scan completed,
        #    create a new Asset automatically.
        #
        # We do NOT create assets for failed/host-down scans.
        #
        # ==================================================

        if selected_asset is None:

            # ------------------------------------------------
            # Look for existing asset by IP
            # ------------------------------------------------

            selected_asset = Asset.query.filter_by(
                ip_address=target
            ).first()


            # ------------------------------------------------
            # Create new Asset only after successful scan
            # ------------------------------------------------

            if (
                selected_asset is None
                and scan_status == "Completed"
            ):

                # --------------------------------------------
                # Generate a safe asset name
                # --------------------------------------------

                asset_name = (
                    f"Discovered Asset - {target}"
                )


                selected_asset = Asset(
                    asset_name=asset_name,
                    ip_address=target
                )


                db.session.add(
                    selected_asset
                )


                # ------------------------------------------------
                # Flush so SQLAlchemy gives us the Asset ID
                # before creating the Scan.
                # ------------------------------------------------

                db.session.flush()


                print(
                    f"[ASSET] Automatically created asset: "
                    f"{asset_name} ({target})"
                )


                log_action(
                    "ASSET_AUTO_CREATED",
                    (
                        f"Asset automatically created from "
                        f"successful vulnerability scan. "
                        f"Asset: {asset_name}. "
                        f"IP: {target}."
                    )
                )


        # ==================================================
        # Store Scan Result
        # ==================================================

        scan = Scan(

            asset_id=(
                selected_asset.id
                if selected_asset
                else None
            ),

            target=target,

            open_ports=open_ports,

            services=services,

            vulnerabilities=vulnerabilities_json,

            risk_level=risk_level,

            max_cvss=max_cvss,

            status=scan_status

        )


        db.session.add(
            scan
        )


        # ==================================================
        # Commit
        # ==================================================

        try:

            db.session.commit()

        except Exception as error:

            db.session.rollback()


            log_action(
                "SCAN_FAILED",
                (
                    f"Database error while saving "
                    f"scan for {target}. "
                    f"Error: {str(error)}"
                )
            )


            flash(
                f"Unable to save scan results for {target}.",
                "danger"
            )


            return redirect(
                url_for(
                    "scanner.scanner"
                )
            )


        # ==================================================
        # Vulnerability Count
        # ==================================================

        vulnerability_count = len(
            vulnerabilities
        )


        # ==================================================
        # Completed
        # ==================================================

        if scan_status == "Completed":

            # ------------------------------------------------
            # Determine display asset name
            # ------------------------------------------------

            if selected_asset:

                display_asset_name = (
                    selected_asset.asset_name
                )

            else:

                display_asset_name = (
                    "Unregistered Target"
                )


            # ------------------------------------------------
            # Audit - Scan Completed
            # ------------------------------------------------

            log_action(
                "SCAN_COMPLETED",
                (
                    f"Vulnerability scan completed. "
                    f"Asset: {display_asset_name}. "
                    f"Target: {target}. "
                    f"Open ports: {open_ports}. "
                    f"Services: {services}. "
                    f"Potential CVEs: "
                    f"{vulnerability_count}. "
                    f"Maximum CVSS: "
                    f"{max_cvss:.1f}. "
                    f"Risk level: "
                    f"{risk_level}."
                )
            )


            # ------------------------------------------------
            # User Message
            # ------------------------------------------------

            if vulnerability_count > 0:

                flash(
                    (
                        f"Scan completed for "
                        f"{target}. "
                        f"{vulnerability_count} potential CVE(s) "
                        f"detected. "
                        f"Maximum CVSS: {max_cvss:.1f}. "
                        f"Risk: {risk_level}."
                    ),
                    "warning"
                )

            else:

                flash(
                    (
                        f"Scan completed successfully for "
                        f"{target}. "
                        f"No applicable CVEs were identified."
                    ),
                    "success"
                )


        # ==================================================
        # Host Down
        # ==================================================

        elif scan_status == "Host Down":

            if selected_asset:

                associated_asset_name = (
                    selected_asset.asset_name
                )

            else:

                associated_asset_name = (
                    "No registered asset"
                )


            log_action(
                "HOST_DOWN",
                (
                    f"Scan target appears unavailable: "
                    f"{target}. "
                    f"Associated asset: "
                    f"{associated_asset_name}."
                )
            )


            flash(
                (
                    f"The target {target} could not "
                    f"be detected."
                ),
                "warning"
            )


        # ==================================================
        # Scan Error
        # ==================================================

        else:

            if selected_asset:

                associated_asset_name = (
                    selected_asset.asset_name
                )

            else:

                associated_asset_name = (
                    "No registered asset"
                )


            log_action(
                "SCAN_FAILED",
                (
                    f"Vulnerability scan failed. "
                    f"Asset: {associated_asset_name}. "
                    f"Target: {target}. "
                    f"Status: {scan_status}. "
                    f"Details: {services}."
                )
            )


            flash(
                f"Scan failed for {target}.",
                "danger"
            )


        # ==================================================
        # Return to Scanner
        # ==================================================

        return redirect(
            url_for(
                "scanner.scanner"
            )
        )


    # ======================================================
    # Scan History
    # ======================================================

    scans = Scan.query.order_by(
        Scan.scan_date.desc()
    ).all()


    # ======================================================
    # Render Scanner
    # ======================================================

    return render_template(
        "scanner.html",
        form=form,
        scans=scans,
        assets=assets
    )