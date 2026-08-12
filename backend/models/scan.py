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

    status = db.Column(
        db.String(20),
        default="Completed"
    )

    # Relationship with Asset
    asset = db.relationship(
        "Asset",
        backref=db.backref(
            "scans",
            lazy=True
        )
    )

    def __repr__(self):

        return f"<Scan {self.target}>"