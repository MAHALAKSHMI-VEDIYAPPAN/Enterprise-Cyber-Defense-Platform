from extensions import db

class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)

    asset_name = db.Column(db.String(100), nullable=False)

    ip_address = db.Column(db.String(50), nullable=False)

    operating_system = db.Column(db.String(100), nullable=False)

    owner = db.Column(db.String(100), nullable=False)

    asset_type = db.Column(db.String(50), nullable=False)

    status = db.Column(db.String(30), default="Active")

    risk_level = db.Column(db.String(20), default="Low")

    def __repr__(self):
        return f"<Asset {self.asset_name}>"