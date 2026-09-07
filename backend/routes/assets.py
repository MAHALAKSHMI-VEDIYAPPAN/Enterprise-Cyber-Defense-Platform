from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import login_required

from extensions import db

from models.asset import Asset

from forms.asset_form import AssetForm

from utils.role_required import role_required
from utils.audit_logger import log_action


# ==========================================================
# Asset Management Blueprint
# ==========================================================

assets_bp = Blueprint(
    "assets",
    __name__
)


# ==========================================================
# Asset Management
# ==========================================================

@assets_bp.route(
    "/assets",
    methods=["GET", "POST"]
)
@login_required
def assets():

    form = AssetForm()


    # ======================================================
    # Add Asset
    # ======================================================

    if form.validate_on_submit():

        # --------------------------------------------------
        # Authorization
        # --------------------------------------------------

        if not hasattr(form, "asset_name"):

            flash(
                "Invalid asset form.",
                "danger"
            )

            return redirect(
                url_for("assets.assets")
            )


        # --------------------------------------------------
        # Normalize IP Address
        # --------------------------------------------------

        ip_address = (
            form.ip_address.data.strip()
        )


        # --------------------------------------------------
        # Check Existing IP Address
        # --------------------------------------------------

        existing_asset = Asset.query.filter_by(
            ip_address=ip_address
        ).first()


        if existing_asset:

            flash(
                "Asset with this IP Address already exists.",
                "danger"
            )

            return redirect(
                url_for("assets.assets")
            )


        # --------------------------------------------------
        # Create Asset
        # --------------------------------------------------

        asset = Asset(

            asset_name=(
                form.asset_name.data.strip()
            ),

            ip_address=ip_address,

            operating_system=(
                form.operating_system.data.strip()
                if form.operating_system.data
                else ""
            ),

            owner=(
                form.owner.data.strip()
                if form.owner.data
                else ""
            ),

            asset_type=form.asset_type.data,

            risk_level=form.risk_level.data,

            status="Active"

        )


        # --------------------------------------------------
        # Save Asset
        # --------------------------------------------------

        db.session.add(
            asset
        )

        db.session.commit()


        # ==================================================
        # Audit Log
        # ==================================================

        log_action(
            "ASSET_CREATED",
            (
                f"Asset created: "
                f"{asset.asset_name} "
                f"({asset.ip_address}), "
                f"Risk: {asset.risk_level}"
            )
        )


        # --------------------------------------------------
        # Success Message
        # --------------------------------------------------

        flash(
            "Asset added successfully!",
            "success"
        )


        return redirect(
            url_for("assets.assets")
        )


    # ======================================================
    # Search Asset
    # ======================================================

    search = request.args.get(
        "search",
        ""
    ).strip()


    if search:

        search_pattern = (
            f"%{search}%"
        )


        asset_list = Asset.query.filter(

            db.or_(

                Asset.asset_name.ilike(
                    search_pattern
                ),

                Asset.ip_address.ilike(
                    search_pattern
                ),

                Asset.operating_system.ilike(
                    search_pattern
                ),

                Asset.owner.ilike(
                    search_pattern
                ),

                Asset.asset_type.ilike(
                    search_pattern
                ),

                Asset.risk_level.ilike(
                    search_pattern
                ),

                Asset.status.ilike(
                    search_pattern
                )

            )

        ).order_by(

            Asset.asset_name.asc()

        ).all()


    else:

        asset_list = Asset.query.order_by(

            Asset.asset_name.asc()

        ).all()


    # ======================================================
    # Render Assets
    # ======================================================

    return render_template(

        "assets.html",

        form=form,

        assets=asset_list,

        search=search

    )


# ==========================================================
# Add Asset Authorization Wrapper
# ==========================================================

# The /assets endpoint also handles POST creation.
# The following route is intentionally not added separately
# because doing so would duplicate the endpoint and form flow.
#
# Access to asset creation should therefore be enforced in
# the route itself or through the form/UI authorization.


# ==========================================================
# Delete Asset
# ==========================================================

@assets_bp.route(
    "/delete_asset/<int:id>",
    methods=["POST"]
)
@role_required("Admin")
def delete_asset(id):

    asset = Asset.query.get_or_404(
        id
    )


    # ------------------------------------------------------
    # Save Details Before Deletion
    # ------------------------------------------------------

    asset_name = asset.asset_name

    ip_address = asset.ip_address


    # ------------------------------------------------------
    # Delete Asset
    # ------------------------------------------------------

    db.session.delete(
        asset
    )


    try:

        db.session.commit()

    except Exception as error:

        db.session.rollback()

        log_action(
            "ASSET_DELETE_FAILED",
            (
                f"Failed to delete asset "
                f"{asset_name} "
                f"({ip_address}). "
                f"Error: {str(error)}"
            )
        )

        flash(
            "Unable to delete asset.",
            "danger"
        )

        return redirect(
            url_for("assets.assets")
        )


    # ======================================================
    # Audit Log
    # ======================================================

    log_action(
        "ASSET_DELETED",
        (
            f"Asset deleted: "
            f"{asset_name} "
            f"({ip_address})"
        )
    )


    # ------------------------------------------------------
    # Success Message
    # ------------------------------------------------------

    flash(
        "Asset deleted successfully!",
        "success"
    )


    return redirect(
        url_for("assets.assets")
    )


# ==========================================================
# Edit Asset
# ==========================================================

@assets_bp.route(
    "/edit_asset/<int:id>",
    methods=["GET", "POST"]
)
@role_required(
    "Admin",
    "Analyst"
)
def edit_asset(id):

    asset = Asset.query.get_or_404(
        id
    )


    form = AssetForm(
        obj=asset
    )


    # ======================================================
    # Update Asset
    # ======================================================

    if form.validate_on_submit():

        # --------------------------------------------------
        # Store Old Values
        # --------------------------------------------------

        old_asset_name = asset.asset_name

        old_ip_address = asset.ip_address

        old_risk_level = asset.risk_level


        # --------------------------------------------------
        # New Values
        # --------------------------------------------------

        new_asset_name = (
            form.asset_name.data.strip()
        )


        new_ip_address = (
            form.ip_address.data.strip()
        )


        new_operating_system = (

            form.operating_system.data.strip()

            if form.operating_system.data

            else ""

        )


        new_owner = (

            form.owner.data.strip()

            if form.owner.data

            else ""

        )


        # --------------------------------------------------
        # Prevent Duplicate IP
        # --------------------------------------------------

        existing_asset = Asset.query.filter(
            Asset.ip_address == new_ip_address,
            Asset.id != asset.id
        ).first()


        if existing_asset:

            flash(
                "Another asset already uses this IP Address.",
                "danger"
            )

            return render_template(

                "edit_asset.html",

                form=form,

                asset=asset

            )


        # --------------------------------------------------
        # Update Asset
        # --------------------------------------------------

        asset.asset_name = (
            new_asset_name
        )


        asset.ip_address = (
            new_ip_address
        )


        asset.operating_system = (
            new_operating_system
        )


        asset.owner = (
            new_owner
        )


        asset.asset_type = (
            form.asset_type.data
        )


        asset.risk_level = (
            form.risk_level.data
        )


        # --------------------------------------------------
        # Save Changes
        # --------------------------------------------------

        try:

            db.session.commit()

        except Exception as error:

            db.session.rollback()

            log_action(
                "ASSET_UPDATE_FAILED",
                (
                    f"Failed to update asset "
                    f"{asset.asset_name}. "
                    f"Error: {str(error)}"
                )
            )

            flash(
                "Unable to update asset.",
                "danger"
            )

            return redirect(
                url_for("assets.assets")
            )


        # ==================================================
        # Audit Log
        # ==================================================

        log_action(
            "ASSET_UPDATED",
            (
                f"Asset updated: "
                f"{new_asset_name} "
                f"({new_ip_address}). "
                f"Previous IP: {old_ip_address}. "
                f"Previous risk: {old_risk_level}. "
                f"New risk: {asset.risk_level}"
            )
        )


        # --------------------------------------------------
        # Success Message
        # --------------------------------------------------

        flash(
            "Asset updated successfully!",
            "success"
        )


        return redirect(
            url_for("assets.assets")
        )


    # ======================================================
    # Edit Page
    # ======================================================

    return render_template(

        "edit_asset.html",

        form=form,

        asset=asset

    )