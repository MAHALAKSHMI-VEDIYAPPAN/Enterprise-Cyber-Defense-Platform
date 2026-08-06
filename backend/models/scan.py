from extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)

    target = db.Column(db.String(100), nullable=False)

    scan_date = db.Column(db.DateTime, server_default=db.func.now())

    open_ports = db.Column(db.Text)

    services = db.Column(db.Text)

    status = db.Column(db.String(20), default="Completed")

    def __repr__(self):
        return f"<Scan {self.target}>"