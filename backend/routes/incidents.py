from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required

from extensions import db
from models.incident import Incident
from forms.incident_form import IncidentForm

incidents_bp = Blueprint("incidents", __name__)


# ----------------------------------------
# Incident Management
# ----------------------------------------

@incidents_bp.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents():

    form = IncidentForm()

    if form.validate_on_submit():

        incident_count = Incident.query.count() + 1

        incident = Incident(

            incident_id=f"INC-{incident_count:04}",

            title=form.title.data,

            asset=form.asset.data,

            severity=form.severity.data,

            assigned_to=form.assigned_to.data,

            description=form.description.data

        )

        db.session.add(incident)
        db.session.commit()

        flash("Incident created successfully!", "success")

        return redirect(url_for("incidents.incidents"))

    search = request.args.get("search")

    if search:

        incident_list = Incident.query.filter(

            Incident.title.contains(search)

        ).all()

    else:

        incident_list = Incident.query.order_by(

            Incident.created_at.desc()

        ).all()

    return render_template(

        "incidents.html",

        form=form,

        incidents=incident_list,

        search=search

    )


# ----------------------------------------
# Delete Incident
# ----------------------------------------

@incidents_bp.route("/delete_incident/<int:id>")
@login_required
def delete_incident(id):

    incident = Incident.query.get_or_404(id)

    db.session.delete(incident)

    db.session.commit()

    flash("Incident deleted successfully!", "success")

    return redirect(url_for("incidents.incidents"))


# ----------------------------------------
# Edit Incident
# ----------------------------------------

@incidents_bp.route("/edit_incident/<int:id>", methods=["GET", "POST"])
@login_required
def edit_incident(id):

    incident = Incident.query.get_or_404(id)

    form = IncidentForm(obj=incident)

    if form.validate_on_submit():

        incident.title = form.title.data
        incident.asset = form.asset.data
        incident.severity = form.severity.data
        incident.assigned_to = form.assigned_to.data
        incident.description = form.description.data

        db.session.commit()

        flash("Incident updated successfully!", "success")

        return redirect(url_for("incidents.incidents"))

    return render_template(

        "edit_incident.html",

        form=form,

        incident=incident

    )