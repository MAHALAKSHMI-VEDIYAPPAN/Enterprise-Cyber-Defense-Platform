from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash
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

from utils.decorators import role_required

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
    # Load Assets into Dropdown
    # ======================================================

    assets = Asset.query.order_by(
        Asset.asset_name.asc()
    ).all()


    form.asset_id.choices = [
        (
            asset.id,
            f"{asset.asset_name} - {asset.ip_address}"
        )
        for asset in assets
    ]


    # ======================================================
    # Handle Asset Selection
    # ======================================================

    if form.asset_id.data:

        selected_asset = Asset.query.get(
            form.asset_id.data
        )


        if selected_asset:

            form.target.data = (
                selected_asset.ip_address
            )


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
                url_for("scanner.scanner")
            )


        # --------------------------------------------------
        # Get Selected Asset
        # --------------------------------------------------

        selected_asset = Asset.query.get(
            form.asset_id.data
        )


        if not selected_asset:

            flash(
                "Selected asset was not found.",
                "danger"
            )

            return redirect(
                url_for("scanner.scanner")
            )


        # --------------------------------------------------
        # Use Asset IP as Target
        # --------------------------------------------------

        target = (
            selected_asset.ip_address.strip()
        )


        if not target:

            flash(
                "The selected asset does not have a valid IP address.",
                "danger"
            )

            return redirect(
                url_for("scanner.scanner")
            )


        # ==================================================
        # Audit - Scan Started
        # ==================================================

        log_action(
            "SCAN_STARTED",
            (
                f"Vulnerability scan started for "
                f"asset {selected_asset.asset_name} "
                f"({target})."
            )
        )


        # ==================================================
        # Run Nmap Scan
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
                    f"asset {selected_asset.asset_name} "
                    f"({target})."
                )
            )


            flash(
                f"Scan failed for {target}.",
                "danger"
            )


            return redirect(
                url_for("scanner.scanner")
            )


        # ==================================================
        # Store Scan Result
        # ==================================================

        scan = Scan(

            asset_id=selected_asset.id,

            target=target,

            open_ports=result.get(
                "open_ports",
                ""
            ),

            services=result.get(
                "services",
                ""
            ),

            status=result.get(
                "status",
                "Failed"
            )

        )


        db.session.add(
            scan
        )

        db.session.commit()


        # ==================================================
        # Scan Status
        # ==================================================

        scan_status = result.get(
            "status",
            "Failed"
        )


        # ==================================================
        # Completed
        # ==================================================

        if scan_status == "Completed":

            log_action(
                "SCAN_COMPLETED",
                (
                    f"Vulnerability scan completed for "
                    f"asset {selected_asset.asset_name} "
                    f"({target}). "
                    f"Open ports: "
                    f"{result.get('open_ports', '')}. "
                    f"Services: "
                    f"{result.get('services', '')}."
                )
            )


            flash(
                f"Scan completed successfully for "
                f"{selected_asset.asset_name} "
                f"({target}).",
                "success"
            )


        # ==================================================
        # Host Down
        # ==================================================

        elif scan_status == "Host Down":

            log_action(
                "HOST_DOWN",
                (
                    f"Scan target appears unavailable: "
                    f"{selected_asset.asset_name} "
                    f"({target})."
                )
            )


            flash(
                f"The target {target} could not "
                f"be detected.",
                "warning"
            )


        # ==================================================
        # Scan Failed
        # ==================================================

        else:

            log_action(
                "SCAN_FAILED",
                (
                    f"Vulnerability scan failed for "
                    f"asset {selected_asset.asset_name} "
                    f"({target}). "
                    f"Status: {scan_status}"
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
            url_for("scanner.scanner")
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

        scans=scans

    )