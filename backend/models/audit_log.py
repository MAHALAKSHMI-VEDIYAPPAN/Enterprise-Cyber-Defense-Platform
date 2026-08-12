from datetime import datetime

from extensions import db


# ==========================================================
# Audit Log Model
# ==========================================================

class AuditLog(db.Model):

    __tablename__ = "audit_logs"


    # ======================================================
    # Primary Key
    # ======================================================

    id = db.Column(
        db.Integer,
        primary_key=True
    )


    # ======================================================
    # User ID
    # ======================================================

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=True
    )


    # ======================================================
    # Username
    # ======================================================

    username = db.Column(
        db.String(100),
        nullable=True
    )


    # ======================================================
    # Action
    # ======================================================

    action = db.Column(
        db.String(100),
        nullable=False
    )


    # ======================================================
    # Description
    # ======================================================

    description = db.Column(
        db.Text,
        nullable=True
    )


    # ======================================================
    # IP Address
    # ======================================================

    ip_address = db.Column(
        db.String(45),
        nullable=True
    )


    # ======================================================
    # Timestamp
    # ======================================================

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )


    # ======================================================
    # Representation
    # ======================================================

    def __repr__(self):

        return (
            f"<AuditLog "
            f"{self.action} "
            f"{self.username}>"
        )