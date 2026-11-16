"""Create the first CampusFind administrator from a local terminal."""

import getpass
import re

from werkzeug.security import generate_password_hash

from app import app
from database import get_db


def main() -> None:
    with app.app_context():
        db = get_db()
        existing_admin = db.execute(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        if existing_admin:
            print("An administrator already exists. No account was changed.")
            return

        print("Create the first CampusFind administrator.")
        full_name = input("Full name: ").strip()
        email = input("Email: ").strip().lower()
        if len(full_name) < 2 or len(full_name) > 80:
            print("Name must be between 2 and 80 characters.")
            return
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            print("Enter a valid email address.")
            return
        password = getpass.getpass("Password (at least 12 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if len(password) < 12 or len(password) > 128:
            print("Password must be between 12 and 128 characters.")
            return
        if password != confirmation:
            print("Passwords did not match.")
            return

        try:
            db.execute(
                """
                INSERT INTO users (full_name, email, password_hash, role)
                VALUES (?, ?, ?, 'admin')
                """,
                (full_name, email, generate_password_hash(password)),
            )
            db.commit()
        except Exception as error:
            db.rollback()
            print(f"Could not create administrator: {error}")
            return
        print("Administrator created. Sign in through the CampusFind website.")


if __name__ == "__main__":
    main()
