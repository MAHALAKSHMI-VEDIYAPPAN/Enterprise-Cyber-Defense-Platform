from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required

from extensions import db
from models.asset import Asset
from forms.asset_form import AssetForm

assets_bp = Blueprint("assets", __name__)


# ==========================================================
# Asset Management
# ==========================================================
@assets_bp.route("/assets", methods=["GET", "POST"])
@login_required
def assets():

    form = AssetForm()

    # ---------------------------
    # Add Asset
    # ---------------------------
    if form.validate_on_submit():

        existing_asset = Asset.query.filter_by(
            ip_address=form.ip_address.data
        ).first()

        if existing_asset:

            flash(
                "Asset with this IP Address already exists.",
                "danger"
            )

            return redirect(url_for("assets.assets"))

        asset = Asset(

            asset_name=form.asset_name.data,

            ip_address=form.ip_address.data,

            operating_system=form.operating_system.data,

            owner=form.owner.data,

            asset_type=form.asset_type.data,

            risk_level=form.risk_level.data,

            status="Active"

        )

        db.session.add(asset)
        db.session.commit()

        flash(
            "Asset added successfully!",
            "success"
        )

        return redirect(url_for("assets.assets"))

    # ---------------------------
    # Search Asset
    # ---------------------------
    search = request.args.get("search")

    if search:

        asset_list = Asset.query.filter(
            Asset.asset_name.contains(search)
        ).order_by(
            Asset.asset_name.asc()
        ).all()

    else:

        asset_list = Asset.query.order_by(
            Asset.asset_name.asc()
        ).all()

    return render_template(
        "assets.html",
        form=form,
        assets=asset_list,
        search=search
    )


# ==========================================================
# Delete Asset
# ==========================================================
@assets_bp.route("/delete_asset/<int:id>")
@login_required
def delete_asset(id):

    asset = Asset.query.get_or_404(id)

    db.session.delete(asset)
    db.session.commit()

    flash(
        "Asset deleted successfully!",
        "success"
    )

    return redirect(url_for("assets.assets"))


# ==========================================================
# Edit Asset
# ==========================================================
@assets_bp.route("/edit_asset/<int:id>", methods=["GET", "POST"])
@login_required
def edit_asset(id):

    asset = Asset.query.get_or_404(id)

    form = AssetForm(obj=asset)

    if form.validate_on_submit():

        asset.asset_name = form.asset_name.data
        asset.ip_address = form.ip_address.data
        asset.operating_system = form.operating_system.data
        asset.owner = form.owner.data
        asset.asset_type = form.asset_type.data
        asset.risk_level = form.risk_level.data

        db.session.commit()

        flash(
            "Asset updated successfully!",
            "success"
        )

        return redirect(url_for("assets.assets"))

    return render_template(
        "edit_asset.html",
        form=form,
        asset=asset
    )