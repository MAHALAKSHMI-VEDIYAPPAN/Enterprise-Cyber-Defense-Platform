from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from extensions import db
from models.asset import Asset
from forms.asset_form import AssetForm

assets_bp = Blueprint("assets", __name__)


@assets_bp.route("/assets", methods=["GET", "POST"])
@login_required
def assets():

    form = AssetForm()

    if form.validate_on_submit():

        asset = Asset(
            asset_name=form.asset_name.data,
            ip_address=form.ip_address.data,
            operating_system=form.operating_system.data,
            owner=form.owner.data,
            asset_type=form.asset_type.data,
            risk_level=form.risk_level.data
        )

        db.session.add(asset)
        db.session.commit()

        flash("Asset added successfully!")

        return redirect(url_for("assets.assets"))

    asset_list = Asset.query.all()

    return render_template(
        "assets.html",
        form=form,
        assets=asset_list
    )