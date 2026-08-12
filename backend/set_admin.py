import sqlite3


# ==========================================================
# Connect to Database
# ==========================================================

connection = sqlite3.connect(
    "database/ecdp.db"
)

cursor = connection.cursor()


# ==========================================================
# Change admin Role
# ==========================================================

cursor.execute(
    """
    UPDATE users
    SET role = ?
    WHERE username = ?
    """,
    ("Admin", "admin")
)


# ==========================================================
# Save Changes
# ==========================================================

connection.commit()


# ==========================================================
# Verify
# ==========================================================

cursor.execute(
    """
    SELECT id, username, email, role
    FROM users
    WHERE username = ?
    """,
    ("admin",)
)

user = cursor.fetchone()


print()
print("=" * 60)
print("ADMIN ROLE UPDATE")
print("=" * 60)

print()

if user:

    print(
        f"ID       : {user[0]}"
    )

    print(
        f"Username : {user[1]}"
    )

    print(
        f"Email    : {user[2]}"
    )

    print(
        f"Role     : {user[3]}"
    )

else:

    print(
        "ERROR: admin user was not found."
    )


print()
print("=" * 60)


# ==========================================================
# Close Database
# ==========================================================

connection.close()