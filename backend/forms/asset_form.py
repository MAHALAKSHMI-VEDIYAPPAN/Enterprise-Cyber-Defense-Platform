from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired


class AssetForm(FlaskForm):

    asset_name = StringField(
        "Asset Name",
        validators=[DataRequired()]
    )

    ip_address = StringField(
        "IP Address",
        validators=[DataRequired()]
    )

    operating_system = StringField(
        "Operating System",
        validators=[DataRequired()]
    )

    owner = StringField(
        "Owner",
        validators=[DataRequired()]
    )

    asset_type = SelectField(
        "Asset Type",
        choices=[
            ("Server", "Server"),
            ("Laptop", "Laptop"),
            ("Desktop", "Desktop"),
            ("Router", "Router"),
            ("Firewall", "Firewall"),
            ("Switch", "Switch")
        ]
    )

    risk_level = SelectField(
        "Risk Level",
        choices=[
            ("Low", "Low"),
            ("Medium", "Medium"),
            ("High", "High"),
            ("Critical", "Critical")
        ]
    )

    submit = SubmitField("Add Asset")