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

ENV_FILE = os.path.join(
    BASE_DIR,
    ".env"
)

load_dotenv(
    ENV_FILE
)


# ==========================================================
# Flask Configuration
# ==========================================================

class Config:

    # ======================================================
    # Flask Secret Key
    # ======================================================

    SECRET_KEY = os.getenv(
        "SECRET_KEY"
    )

    if not SECRET_KEY:

        raise RuntimeError(
            "SECRET_KEY is not configured. "
            "Please add SECRET_KEY to the .env file."
        )


    # ======================================================
    # Debug Configuration
    # ======================================================

    DEBUG = os.getenv(
        "FLASK_DEBUG",
        "False"
    ).lower() == "true"


    # ======================================================
    # Testing
    # ======================================================

    TESTING = False


    # ======================================================
    # Session Security
    # ======================================================

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Lax"

    SESSION_COOKIE_SECURE = os.getenv(
        "SESSION_COOKIE_SECURE",
        "False"
    ).lower() == "true"

    SESSION_REFRESH_EACH_REQUEST = True


    # ======================================================
    # Flask-Login Session Protection
    # ======================================================

    SESSION_PROTECTION = "strong"


    # ======================================================
    # CSRF Protection
    # ======================================================

    WTF_CSRF_ENABLED = True

    WTF_CSRF_TIME_LIMIT = 3600


    # ======================================================
    # Request Size Protection
    # ======================================================

    MAX_CONTENT_LENGTH = 2 * 1024 * 1024


    # ======================================================
    # SQLite Database
    # ======================================================

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///"
        + os.path.join(
            BASE_DIR,
            "database",
            "ecdp.db"
        )
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False


    # ======================================================
    # OpenAI Configuration
    # ======================================================

    OPENAI_API_KEY = os.getenv(
        "OPENAI_API_KEY"
    )

    OPENAI_MODEL = os.getenv(
        "OPENAI_MODEL",
        "gpt-4o-mini"
    )


    # ======================================================
    # VirusTotal API
    # ======================================================

    VIRUSTOTAL_API_KEY = os.getenv(
        "VIRUSTOTAL_API_KEY"
    )

    VIRUSTOTAL_REFRESH_ANALYSIS = os.getenv(
        "VIRUSTOTAL_REFRESH_ANALYSIS",
        "False"
    ).lower() == "true"


    # ======================================================
    # NVD API
    # ======================================================

    NVD_API_KEY = os.getenv(
        "NVD_API_KEY"
    )