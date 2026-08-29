from extensions import db


class Scan(db.Model):

    __tablename__ = "scans"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # Link scan to an enterprise asset
    asset_id = db.Column(
        db.Integer,
        db.ForeignKey("assets.id"),
        nullable=True
    )

    target = db.Column(
        db.String(100),
        nullable=False
    )

    scan_date = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    open_ports = db.Column(
        db.Text
    )

    services = db.Column(
        db.Text
    )

    # ------------------------------------------------------
    # Potential CVE matches returned by NVD
    # Stored as JSON text
    # ------------------------------------------------------

    vulnerabilities = db.Column(
        db.Text,
        default="[]"
    )

    # ------------------------------------------------------
    # ECDP application-level risk
    # ------------------------------------------------------

    risk_level = db.Column(
        db.String(20),
        default="LOW"
    )

    # ------------------------------------------------------
    # Highest CVSS score found
    # ------------------------------------------------------

    max_cvss = db.Column(
        db.Float,
        default=0.0
    )

    status = db.Column(
        db.String(20),
        default="Completed"
    )

    # ======================================================
    # Relationship with Asset
    # ======================================================

    asset = db.relationship(
        "Asset",
        backref=db.backref(
            "scans",
            lazy=True
        )
    )

    def __repr__(self):

        return f"<Scan {self.target}>"