import sqlite3

from pathlib import Path


# ==========================================================
# ECDP Scan Database Migration
# ==========================================================

BASE_DIR = Path(
    __file__
).resolve().parent


DATABASE = (
    BASE_DIR
    / "database"
    / "ecdp.db"
)


# ==========================================================
# Migration
# ==========================================================

def migrate():

    print(
        "Database:"
    )

    print(
        DATABASE
    )


    # ------------------------------------------------------
    # Check Database
    # ------------------------------------------------------

    if not DATABASE.exists():

        print(
            "ERROR: Database file was not found."
        )

        return


    connection = sqlite3.connect(
        DATABASE
    )


    try:

        cursor = connection.cursor()


        # ==================================================
        # Check Existing Columns
        # ==================================================

        cursor.execute(
            "PRAGMA table_info(scans)"
        )


        existing_columns = {

            row[1]

            for row in cursor.fetchall()

        }


        print(
            "\nExisting scans columns:"
        )


        for column in existing_columns:

            print(
                f"  - {column}"
            )


        # ==================================================
        # Add vulnerabilities
        # ==================================================

        if "vulnerabilities" not in existing_columns:

            cursor.execute(
                """
                ALTER TABLE scans
                ADD COLUMN vulnerabilities
                TEXT DEFAULT '[]'
                """
            )

            print(
                "[ADDED] vulnerabilities"
            )

        else:

            print(
                "[SKIP] vulnerabilities already exists"
            )


        # ==================================================
        # Add risk_level
        # ==================================================

        if "risk_level" not in existing_columns:

            cursor.execute(
                """
                ALTER TABLE scans
                ADD COLUMN risk_level
                VARCHAR(20) DEFAULT 'LOW'
                """
            )

            print(
                "[ADDED] risk_level"
            )

        else:

            print(
                "[SKIP] risk_level already exists"
            )


        # ==================================================
        # Add max_cvss
        # ==================================================

        if "max_cvss" not in existing_columns:

            cursor.execute(
                """
                ALTER TABLE scans
                ADD COLUMN max_cvss
                FLOAT DEFAULT 0.0
                """
            )

            print(
                "[ADDED] max_cvss"
            )

        else:

            print(
                "[SKIP] max_cvss already exists"
            )


        # ==================================================
        # Save
        # ==================================================

        connection.commit()


        print(
            "\n=========================================="
        )

        print(
            "SCAN DATABASE MIGRATION COMPLETED"
        )

        print(
            "=========================================="
        )


    except Exception as error:

        connection.rollback()

        print(
            "\nMIGRATION FAILED:"
        )

        print(
            error
        )

        raise


    finally:

        connection.close()


# ==========================================================
# Run
# ==========================================================

if __name__ == "__main__":

    migrate()