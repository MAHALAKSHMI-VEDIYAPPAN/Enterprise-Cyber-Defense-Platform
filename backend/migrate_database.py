import sqlite3
import os

from config import BASE_DIR


# ==========================================================
# Database Path
# ==========================================================

database_path = os.path.join(
    BASE_DIR,
    "database",
    "ecdp.db"
)


print("=" * 60)
print("ECDP DATABASE MIGRATION")
print("=" * 60)

print(
    f"Database: {database_path}"
)


# ==========================================================
# Check Database
# ==========================================================

if not os.path.exists(database_path):

    print(
        "ERROR: Database file was not found."
    )

    print(
        "Expected:"
    )

    print(
        database_path
    )

    raise SystemExit(1)


# ==========================================================
# Connect to Database
# ==========================================================

connection = sqlite3.connect(
    database_path
)

cursor = connection.cursor()


# ==========================================================
# USERS TABLE MIGRATION
# ==========================================================

print()
print("=" * 60)
print("USERS TABLE MIGRATION")
print("=" * 60)


# ==========================================================
# Get Existing User Columns
# ==========================================================

cursor.execute(
    "PRAGMA table_info(users)"
)

columns = [
    row[1]
    for row in cursor.fetchall()
]


print()
print("Existing users table columns:")

for column in columns:

    print(
        f"  - {column}"
    )


# ==========================================================
# Add Failed Login Attempts
# ==========================================================

if "failed_login_attempts" not in columns:

    print()
    print(
        "Adding failed_login_attempts..."
    )

    cursor.execute(
        """
        ALTER TABLE users
        ADD COLUMN failed_login_attempts
        INTEGER NOT NULL DEFAULT 0
        """
    )

    print(
        "Added successfully."
    )

else:

    print(
        "failed_login_attempts already exists."
    )


# ==========================================================
# Add Account Lock Time
# ==========================================================

if "locked_until" not in columns:

    print()
    print(
        "Adding locked_until..."
    )

    cursor.execute(
        """
        ALTER TABLE users
        ADD COLUMN locked_until
        DATETIME
        """
    )

    print(
        "Added successfully."
    )

else:

    print(
        "locked_until already exists."
    )


# ==========================================================
# AUDIT LOG TABLE
# ==========================================================

print()
print("=" * 60)
print("AUDIT LOG TABLE MIGRATION")
print("=" * 60)


# ==========================================================
# Check Whether audit_logs Table Exists
# ==========================================================

cursor.execute(
    """
    SELECT name
    FROM sqlite_master
    WHERE type='table'
    AND name='audit_logs'
    """
)

audit_table = cursor.fetchone()


# ==========================================================
# Create Audit Logs Table
# ==========================================================

if not audit_table:

    print()
    print(
        "Creating audit_logs table..."
    )

    cursor.execute(
        """
        CREATE TABLE audit_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            username VARCHAR(100),

            action VARCHAR(100) NOT NULL,

            description TEXT,

            ip_address VARCHAR(45),

            timestamp DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)

        )
        """
    )

    print(
        "audit_logs table created successfully."
    )

else:

    print(
        "audit_logs table already exists."
    )


# ==========================================================
# Verify Audit Log Table
# ==========================================================

cursor.execute(
    "PRAGMA table_info(audit_logs)"
)

audit_columns = [
    row[1]
    for row in cursor.fetchall()
]


print()
print("Audit logs table columns:")

for column in audit_columns:

    print(
        f"  - {column}"
    )


# ==========================================================
# Save Changes
# ==========================================================

connection.commit()


# ==========================================================
# Verify Users Migration
# ==========================================================

cursor.execute(
    "PRAGMA table_info(users)"
)

updated_columns = [
    row[1]
    for row in cursor.fetchall()
]


print()
print("=" * 60)
print("UPDATED USERS TABLE")
print("=" * 60)

for column in updated_columns:

    print(
        f"  - {column}"
    )


# ==========================================================
# Verify Audit Log Count
# ==========================================================

cursor.execute(
    "SELECT COUNT(*) FROM audit_logs"
)

audit_count = cursor.fetchone()[0]


print()
print(
    f"Current audit log records: {audit_count}"
)


# ==========================================================
# Close Database
# ==========================================================

connection.close()


print()
print("=" * 60)
print("DATABASE MIGRATION COMPLETED")
print("=" * 60)