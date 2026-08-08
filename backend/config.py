import os
from dotenv import load_dotenv


# ==========================================================
# Base Directory
# ==========================================================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


# ==========================================================
# Load Environment Variables
# ==========================================================

load_dotenv(
    os.path.join(
        BASE_DIR,
        ".env"
    )
)


# ==========================================================
# Flask Configuration
# ==========================================================

class Config:

    # Flask Secret Key
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "ecdp-development-secret-key"
    )

    # SQLite Database
    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///"
        + os.path.join(
            BASE_DIR,
            "database",
            "ecdp.db"
        )
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # VirusTotal API
    VIRUSTOTAL_API_KEY = os.getenv(
        "VIRUSTOTAL_API_KEY"
    )