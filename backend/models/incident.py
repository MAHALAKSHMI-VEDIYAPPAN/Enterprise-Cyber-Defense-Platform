from extensions import db
from datetime import datetime


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)

    incident_id = db.Column(db.String(20), unique=True)

    title = db.Column(db.String(200), nullable=False)

    asset = db.Column(db.String(100))

    severity = db.Column(db.String(20))

    status = db.Column(db.String(30), default="Open")

    assigned_to = db.Column(db.String(100))

    description = db.Column(db.Text)

    resolution = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    def __repr__(self):
        return f"<Incident {self.incident_id}>"