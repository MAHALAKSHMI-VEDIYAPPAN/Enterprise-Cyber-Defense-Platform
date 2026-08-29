from datetime import datetime

from extensions import db


class Remediation(db.Model):

    __tablename__ = "remediations"

    # ==========================================================
    # Primary Key
    # ==========================================================

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # ==========================================================
    # Remediation ID
    # ==========================================================

    remediation_id = db.Column(
        db.String(30),
        unique=True,
        nullable=False
    )

    # ==========================================================
    # Title
    # ==========================================================

    title = db.Column(
        db.String(200),
        nullable=False
    )

    # ==========================================================
    # CVE
    # ==========================================================

    cve_id = db.Column(
        db.String(50),
        nullable=True
    )

    # ==========================================================
    # Asset
    # ==========================================================

    asset_id = db.Column(
        db.Integer,
        db.ForeignKey("assets.id"),
        nullable=True
    )

    # ==========================================================
    # Scan
    # ==========================================================

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=True
    )

    # ==========================================================
    # Incident
    # ==========================================================

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incidents.id"),
        nullable=True
    )

    # ==========================================================
    # Severity
    # ==========================================================

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="Medium"
    )

    # ==========================================================
    # Description
    # ==========================================================

    description = db.Column(
        db.Text,
        nullable=True
    )

    # ==========================================================
    # Recommendation
    # ==========================================================

    recommendation = db.Column(
        db.Text,
        nullable=True
    )

    # ==========================================================
    # Status
    # ==========================================================

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Open"
    )

    # ==========================================================
    # Assigned Analyst
    # ==========================================================

    assigned_to = db.Column(
        db.String(100),
        nullable=True
    )

    # ==========================================================
    # Notes
    # ==========================================================

    notes = db.Column(
        db.Text,
        nullable=True
    )

    # ==========================================================
    # Verification Notes
    # ==========================================================

    verification_notes = db.Column(
        db.Text,
        nullable=True
    )

    # ==========================================================
    # Verification Timestamp
    # ==========================================================

    verified_at = db.Column(
        db.DateTime,
        nullable=True
    )

    # ==========================================================
    # Created
    # ==========================================================

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # ==========================================================
    # Updated
    # ==========================================================

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # ==========================================================
    # Relationships
    # ==========================================================

    asset = db.relationship(
        "Asset",
        backref=db.backref(
            "remediations",
            lazy=True
        )
    )

    scan = db.relationship(
        "Scan",
        backref=db.backref(
            "remediations",
            lazy=True
        )
    )

    incident = db.relationship(
        "Incident",
        backref=db.backref(
            "remediations",
            lazy=True
        )
    )

    # ==========================================================
    # Representation
    # ==========================================================

    def __repr__(self):

        return (
            f"<Remediation "
            f"{self.remediation_id}>"
        )