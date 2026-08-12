from datetime import datetime

from extensions import db


# ==========================================================
# Incident Model
# ==========================================================

class Incident(db.Model):

    __tablename__ = "incidents"


    # ======================================================
    # Primary Key
    # ======================================================

    id = db.Column(
        db.Integer,
        primary_key=True
    )


    # ======================================================
    # Incident ID
    # ======================================================

    incident_id = db.Column(
        db.String(20),
        unique=True,
        nullable=False
    )


    # ======================================================
    # Incident Title
    # ======================================================

    title = db.Column(
        db.String(200),
        nullable=False
    )


    # ======================================================
    # Affected Asset
    # ======================================================

    asset = db.Column(
        db.String(100)
    )


    # ======================================================
    # Severity
    # ======================================================

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="Medium"
    )


    # ======================================================
    # Status
    # ======================================================

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Open"
    )


    # ======================================================
    # Assigned Analyst
    # ======================================================

    assigned_to = db.Column(
        db.String(100)
    )


    # ======================================================
    # Description
    # ======================================================

    description = db.Column(
        db.Text
    )


    # ======================================================
    # Resolution
    # ======================================================

    resolution = db.Column(
        db.Text
    )


    # ======================================================
    # Created Timestamp
    # ======================================================

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )


    # ======================================================
    # Updated Timestamp
    # ======================================================

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )


    # ======================================================
    # String Representation
    # ======================================================

    def __repr__(self):

        return f"<Incident {self.incident_id}>"