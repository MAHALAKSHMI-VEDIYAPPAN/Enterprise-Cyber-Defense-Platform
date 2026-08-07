import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load variables from .env
load_dotenv(os.path.join(BASE_DIR, ".env"))

class Config:

    SECRET_KEY = "ecdp_secret_key_2026"

    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
        BASE_DIR,
        "database",
        "ecdp.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")