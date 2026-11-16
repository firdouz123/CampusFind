"""CampusFind: a small, beginner-friendly Flask lost-and-found app."""

from __future__ import annotations

import os
import re
import hashlib
import logging
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import close_db, get_db

BASE_DIR = Path(__file__).resolve().parent
CATEGORIES = [
    "Electronics",
    "ID & Cards",
    "Keys",
    "Bags",
    "Clothing",
    "Books",
    "Jewelry",
    "Sports",
    "Other",
]
MAX_IMAGE_BYTES = 3 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {"jpg", "jpeg", "png", "webp"}
RECOVERY_CODE_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def generate_recovery_code() -> str:
    """Generate a cryptographically secure 16-character recovery code in 4 blocks (e.g. ABCD-EFGH-JKLM-NPQR)."""
    blocks = [
        "".join(secrets.choice(RECOVERY_CODE_CHARS) for _ in range(4))
        for _ in range(4)
    ]
    return "-".join(blocks)


def normalize_recovery_code(code: str) -> str:
    """Strip spaces, dashes, and normalize code to uppercase."""
    return re.sub(r"[^A-Za-z0-9]", "", code or "").upper()


def hash_recovery_code(code: str) -> str:
    """Return a SHA-256 hash of the normalized recovery code."""
    normalized = normalize_recovery_code(code)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        instance_path=str(BASE_DIR / "instance"),
        instance_relative_config=True,
    )
    app.logger.setLevel(logging.WARNING)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    upload_dir = BASE_DIR / "static" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SESSION_SECRET") or secrets.token_hex(32),
        DATABASE=os.environ.get(
            "CAMPUSFIND_DB", str(Path(app.instance_path) / "campusfind.sqlite3")
        ),
        UPLOAD_FOLDER=str(upload_dir),
        MAX_CONTENT_LENGTH=MAX_IMAGE_BYTES + 128 * 1024,
        SESSION_COOKIE_NAME=os.environ.get("SESSION_COOKIE_NAME", "session"),
        SESSION_COOKIE_HTTPONLY=True,
        # The Replit preview is embedded cross-site and sets these through its
        # artifact environment; first-party laptop runs can safely use Lax.
        SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0").lower()
        in {"1", "true", "yes"},
        SESSION_COOKIE_PARTITIONED=os.environ.get(
            "SESSION_COOKIE_PARTITIONED", "0"
        ).lower()
        in {"1", "true", "yes"},
        PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    )
    if test_config:
        app.config.update(test_config)

    app.teardown_appcontext(close_db)

    with app.app_context():
        schema = (BASE_DIR / "schema.sql").read_text(encoding="utf-8")
        get_db().executescript(schema)
        get_db().commit()

    @app.before_request
    def load_logged_in_user() -> None:
        user_id = session.get("user_id")
        g.user = None
        if user_id is not None:
            g.user = get_db().execute(
                "SELECT id, full_name, email, role, is_active FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if g.user is None or not g.user["is_active"]:
                session.clear()
                g.user = None

    @app.before_request
    def protect_forms_from_csrf() -> None:
        if request.method in {"GET", "HEAD", "OPTIONS"} or request.endpoint == "static":
            return
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        expected = session.get("_csrf_token")
        if not submitted or not expected or not secrets.compare_digest(submitted, expected):
            abort(400, description="Your form has expired. Refresh the page and try again.")

    @app.context_processor
    def provide_template_helpers() -> dict:
        def csrf_token() -> str:
            if "_csrf_token" not in session:
                session["_csrf_token"] = secrets.token_urlsafe(32)
            return session["_csrf_token"]

        def user_has_recovery_code() -> bool:
            if not g.user:
                return False
            row = get_db().execute(
                "SELECT 1 FROM recovery_codes WHERE user_id = ?",
                (g.user["id"],),
            ).fetchone()
            return row is not None

        return {
            "csrf_token": csrf_token,
            "categories": CATEGORIES,
            "current_year": date.today().year,
            "user_has_recovery_code": user_has_recovery_code,
        }

    def login_required(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if g.user is None:
                flash("Sign in to continue.", "info")
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped_view

    def admin_required(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if g.user is None:
                flash("Sign in to continue.", "info")
                return redirect(url_for("login", next=request.path))
            if g.user["role"] != "admin":
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    def safe_next_url(target: str | None) -> str | None:
        if target and target.startswith("/") and not target.startswith("//"):
            return target
        return None

    def item_by_id(item_id: int):
        item = get_db().execute(
            """
            SELECT items.*, users.full_name AS owner_name
            FROM items JOIN users ON users.id = items.owner_id
            WHERE items.id = ?
            """,
            (item_id,),
        ).fetchone()
        if item is None:
            abort(404)
        return item

    def can_manage(item) -> bool:
        return bool(
            g.user
            and (
                g.user["role"] == "admin"
                or item["owner_id"] == g.user["id"]
            )
        )

    def filtered_items(condition: str, query: str, category: str, location: str):
        clauses = [condition, "items.is_hidden = 0"]
        values: list = []
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            clauses.append(
                "(items.title LIKE ? ESCAPE '\\' OR items.description LIKE ? ESCAPE '\\' "
                "OR items.category LIKE ? ESCAPE '\\' OR items.location LIKE ? ESCAPE '\\')"
            )
            values.extend([like, like, like, like])
        if category in CATEGORIES:
            clauses.append("items.category = ?")
            values.append(category)
        if location:
            clauses.append("items.location = ?")
            values.append(location)
        return get_db().execute(
            f"""
            SELECT items.*, users.full_name AS owner_name
            FROM items JOIN users ON users.id = items.owner_id
            WHERE {" AND ".join(clauses)}
            ORDER BY CASE WHEN items.status = 'returned' THEN 1 ELSE 0 END,
                     items.created_at DESC
            LIMIT 60
            """,
            values,
        ).fetchall()

    def image_magic_matches(extension: str, content: bytes) -> bool:
        if extension == "png":
            return content.startswith(b"\x89PNG\r\n\x1a\n")
        if extension in {"jpg", "jpeg"}:
            return content.startswith(b"\xff\xd8\xff")
        if extension == "webp":
            return len(content) > 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP"
        return False

    def save_uploaded_image():
        uploaded = request.files.get("image")
        if not uploaded or not uploaded.filename:
            return None, None
        extension = Path(uploaded.filename).suffix.lower().lstrip(".")
        if extension not in ALLOWED_IMAGE_TYPES:
            return None, "Choose a JPG, PNG, or WebP image."
        content = uploaded.stream.read(MAX_IMAGE_BYTES + 1)
        if len(content) > MAX_IMAGE_BYTES:
            return None, "Images must be 3 MB or smaller."
        if not image_magic_matches(extension, content):
            return None, "The selected file is not a supported image."
        stored_name = f"{uuid.uuid4().hex}.{extension}"
        destination = Path(app.config["UPLOAD_FOLDER"]) / stored_name
        destination.write_bytes(content)
        return stored_name, None

    def remove_image(filename: str | None) -> None:
        if filename:
            try:
                (Path(app.config["UPLOAD_FOLDER"]) / Path(filename).name).unlink()
            except FileNotFoundError:
                pass

    def validate_item_form(form) -> dict[str, str]:
        data = {
            "kind": form.get("kind", "").strip(),
            "title": form.get("title", "").strip(),
            "description": form.get("description", "").strip(),
            "category": form.get("category", "").strip(),
            "location": form.get("location", "").strip(),
            "item_date": form.get("item_date", "").strip(),
        }
        errors = []
        if data["kind"] not in {"lost", "found"}:
            errors.append("Choose whether you lost or found the item.")
        if not 3 <= len(data["title"]) <= 100:
            errors.append("The title must be between 3 and 100 characters.")
        if not 10 <= len(data["description"]) <= 1200:
            errors.append("The description must be between 10 and 1,200 characters.")
        if data["category"] not in CATEGORIES:
            errors.append("Choose a category from the list.")
        if not 2 <= len(data["location"]) <= 120:
            errors.append("The location must be between 2 and 120 characters.")
        try:
            parsed_date = datetime.strptime(data["item_date"], "%Y-%m-%d").date()
            if parsed_date > date.today():
                errors.append("The item date cannot be in the future.")
        except ValueError:
            errors.append("Enter a valid date.")
        if errors:
            raise ValueError(" ".join(errors))
        return data

    @app.route("/")
    def home():
        query = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "").strip()
        location = request.args.get("location", "").strip()[:120]
        lost_items = filtered_items(
            "items.kind = 'lost' AND items.status = 'active'",
            query,
            category,
            location,
        )
        found_items = filtered_items(
            "((items.kind = 'found' AND items.status = 'found') "
            "OR (items.kind = 'lost' AND items.status = 'found'))",
            query,
            category,
            location,
        )
        returned_items = filtered_items(
            "items.status = 'returned'", query, category, location
        )
        locations = get_db().execute(
            "SELECT DISTINCT location FROM items WHERE is_hidden = 0 ORDER BY location"
        ).fetchall()
        return render_template(
            "home.html",
            lost_items=lost_items,
            found_items=found_items,
            returned_items=returned_items,
            query=query,
            selected_category=category,
            selected_location=location,
            locations=locations,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("home"))
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            errors = []
            if not 2 <= len(full_name) <= 80:
                errors.append("Your name must be between 2 and 80 characters.")
            if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                errors.append("Enter a valid email address.")
            if len(password) < 8 or len(password) > 128:
                errors.append("Your password must be between 8 and 128 characters.")
            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("register.html")

            db = get_db()
            # Explicit pre-check: verify if an account with this email already exists (case-insensitive)
            existing_user = db.execute(
                "SELECT id FROM users WHERE email = ? COLLATE NOCASE",
                (email,),
            ).fetchone()
            if existing_user is not None:
                flash("An account with that email already exists.", "error")
                return render_template("register.html")

            try:
                cursor = db.execute(
                    """
                    INSERT INTO users (full_name, email, password_hash, role)
                    VALUES (?, ?, ?, 'student')
                    """,
                    (full_name, email, generate_password_hash(password)),
                )
                user_id = cursor.lastrowid
                recovery_code = generate_recovery_code()
                code_hash = hash_recovery_code(recovery_code)
                db.execute(
                    """
                    INSERT INTO recovery_codes (user_id, code_hash)
                    VALUES (?, ?)
                    """,
                    (user_id, code_hash),
                )
                db.commit()
            except sqlite3.IntegrityError as error:
                db.rollback()
                if "email" in str(error).lower():
                    flash("An account with that email already exists.", "error")
                else:
                    app.logger.warning("Registration constraint error: %s", error)
                    flash("Could not complete registration. Please try again.", "error")
                return render_template("register.html")
            except Exception as error:
                db.rollback()
                app.logger.error("Unexpected registration error: %s", error)
                flash("Could not complete registration. Please try again.", "error")
                return render_template("register.html")

            session.clear()
            session["user_id"] = user_id
            session["new_recovery_code"] = recovery_code
            session["is_new_registration"] = True
            flash("Your student account is ready. Save your recovery code below.", "success")
            return redirect(url_for("recovery_code_display"))
        return render_template("register.html")

    @app.route("/recovery-code")
    @login_required
    def recovery_code_display():
        code = session.pop("new_recovery_code", None)
        is_new = session.pop("is_new_registration", False)
        if not code:
            flash(
                "For your security, recovery codes can only be displayed once when generated.",
                "info",
            )
            return redirect(url_for("account_recovery_code"))
        return render_template(
            "recovery_code.html",
            recovery_code=code,
            is_new=is_new,
        )

    @app.route("/account/recovery-code", methods=["GET", "POST"])
    @login_required
    def account_recovery_code():
        db = get_db()
        existing_code = db.execute(
            "SELECT id, created_at, updated_at FROM recovery_codes WHERE user_id = ?",
            (g.user["id"],),
        ).fetchone()

        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            user = db.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (g.user["id"],),
            ).fetchone()
            if not user or not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect. Please verify your password to continue.", "error")
                return render_template(
                    "account_security.html",
                    has_code=bool(existing_code),
                    existing_code=existing_code,
                )

            new_code = generate_recovery_code()
            new_hash = hash_recovery_code(new_code)
            if existing_code:
                db.execute(
                    """
                    UPDATE recovery_codes
                    SET code_hash = ?, failed_attempts = 0, locked_until = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                    """,
                    (new_hash, g.user["id"]),
                )
            else:
                db.execute(
                    """
                    INSERT INTO recovery_codes (user_id, code_hash, failed_attempts, locked_until)
                    VALUES (?, ?, 0, 0)
                    """,
                    (g.user["id"], new_hash),
                )
            db.commit()
            session["new_recovery_code"] = new_code
            session["is_new_registration"] = False
            flash("A new recovery code has been generated. Any previous code is now permanently invalidated.", "success")
            return redirect(url_for("recovery_code_display"))

        return render_template(
            "account_security.html",
            has_code=bool(existing_code),
            existing_code=existing_code,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("home"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            if (
                user is None
                or not user["is_active"]
                or not check_password_hash(user["password_hash"], password)
            ):
                flash("Email or password is incorrect.", "error")
                return render_template("login.html")
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['full_name'].split()[0]}.", "success")
            return redirect(safe_next_url(request.args.get("next")) or url_for("home"))
        return render_template("login.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if g.user:
            return redirect(url_for("home"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            recovery_code = request.form.get("recovery_code", "").strip()
            password = request.form.get("password", "")
            confirmation = request.form.get("confirm_password", "")

            errors = []
            if not email or len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                errors.append("Enter a valid email address.")
            if not recovery_code:
                errors.append("Enter your recovery code.")
            if not 8 <= len(password) <= 128:
                errors.append("Your new password must be between 8 and 128 characters.")
            if password != confirmation:
                errors.append("The new passwords do not match.")

            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("forgot_password.html", email=email)

            db = get_db()
            user = db.execute(
                "SELECT id, full_name, email, is_active FROM users WHERE email = ?",
                (email,),
            ).fetchone()

            if user is None or not user["is_active"]:
                flash("Invalid email or recovery code.", "error")
                return render_template("forgot_password.html", email=email)

            rec = db.execute(
                "SELECT id, code_hash, failed_attempts, locked_until FROM recovery_codes WHERE user_id = ?",
                (user["id"],),
            ).fetchone()

            if rec is None:
                flash(
                    "No recovery code is registered for this account. Please contact campus support.",
                    "error",
                )
                return render_template("forgot_password.html", email=email)

            now = int(datetime.now(timezone.utc).timestamp())
            if rec["locked_until"] > now:
                minutes_left = max(1, (rec["locked_until"] - now + 59) // 60)
                flash(
                    f"Too many failed recovery attempts. Account recovery is temporarily locked for {minutes_left} minute(s). Please try again later.",
                    "error",
                )
                return render_template("forgot_password.html", email=email)

            entered_hash = hash_recovery_code(recovery_code)
            if not secrets.compare_digest(entered_hash, rec["code_hash"]):
                new_failed = rec["failed_attempts"] + 1
                new_locked = (now + 900) if new_failed >= 5 else 0
                db.execute(
                    """
                    UPDATE recovery_codes
                    SET failed_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (new_failed, new_locked, rec["id"]),
                )
                db.commit()
                if new_failed >= 5:
                    flash("Too many failed attempts. Account recovery has been locked for 15 minutes.", "error")
                else:
                    remaining = 5 - new_failed
                    flash(f"Invalid recovery code. {remaining} attempt(s) remaining before temporary lockout.", "error")
                return render_template("forgot_password.html", email=email)

            # Code verified! Update password and permanently invalidate this code
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), user["id"]),
            )
            db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
            db.commit()
            session.clear()
            flash("Your password has been reset successfully. Please sign in with your new password.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html", email="")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        flash("You have been signed out.", "info")
        return redirect(url_for("home"))

    @app.route("/items/new", methods=["GET", "POST"])
    @login_required
    def create_item():
        if request.method == "POST":
            try:
                data = validate_item_form(request.form)
            except ValueError as error:
                flash(str(error), "error")
                return render_template("item_form.html", item=None)
            image_name, image_error = save_uploaded_image()
            if image_error:
                flash(image_error, "error")
                return render_template("item_form.html", item=None)
            status = "active" if data["kind"] == "lost" else "found"
            cursor = get_db().execute(
                """
                INSERT INTO items
                    (owner_id, kind, status, title, description, category, location,
                     item_date, image_filename)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    g.user["id"],
                    data["kind"],
                    status,
                    data["title"],
                    data["description"],
                    data["category"],
                    data["location"],
                    data["item_date"],
                    image_name,
                ),
            )
            get_db().commit()
            flash("Your report has been posted.", "success")
            return redirect(url_for("item_detail", item_id=cursor.lastrowid))
        return render_template("item_form.html", item=None)

    @app.route("/items/<int:item_id>")
    def item_detail(item_id: int):
        item = item_by_id(item_id)
        if item["is_hidden"] and not can_manage(item):
            abort(404)
        return render_template("item_detail.html", item=item)

    @app.route("/items/<int:item_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_item(item_id: int):
        item = item_by_id(item_id)
        if item["owner_id"] != g.user["id"]:
            abort(403)
        if item["is_hidden"]:
            abort(404)
        if request.method == "POST":
            try:
                data = validate_item_form(request.form)
            except ValueError as error:
                flash(str(error), "error")
                return render_template("item_form.html", item=item)
            new_image, image_error = save_uploaded_image()
            if image_error:
                flash(image_error, "error")
                return render_template("item_form.html", item=item)
            image_name = new_image or item["image_filename"]
            get_db().execute(
                """
                UPDATE items SET kind = ?, title = ?, description = ?, category = ?,
                    location = ?, item_date = ?, image_filename = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND owner_id = ?
                """,
                (
                    data["kind"],
                    data["title"],
                    data["description"],
                    data["category"],
                    data["location"],
                    data["item_date"],
                    image_name,
                    item_id,
                    g.user["id"],
                ),
            )
            get_db().commit()
            if new_image:
                remove_image(item["image_filename"])
            flash("Your report has been updated.", "success")
            return redirect(url_for("my_reports"))
        return render_template("item_form.html", item=item)

    @app.route("/items/<int:item_id>/status", methods=["POST"])
    @login_required
    def update_item_status(item_id: int):
        item = item_by_id(item_id)
        if item["owner_id"] != g.user["id"]:
            abort(403)
        if item["status"] == "active":
            next_status = "found"
        elif item["status"] == "found":
            next_status = "returned"
        else:
            abort(400, description="Returned reports cannot be changed.")
        get_db().execute(
            "UPDATE items SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (next_status, item_id),
        )
        get_db().commit()
        message = "Marked as found." if next_status == "found" else "Marked as returned."
        flash(message, "success")
        return redirect(url_for("my_reports"))

    @app.route("/items/<int:item_id>/delete", methods=["POST"])
    @login_required
    def delete_item(item_id: int):
        item = item_by_id(item_id)
        if item["owner_id"] != g.user["id"]:
            abort(403)
        get_db().execute("DELETE FROM items WHERE id = ?", (item_id,))
        get_db().commit()
        remove_image(item["image_filename"])
        flash("The report has been deleted.", "success")
        return redirect(url_for("my_reports"))

    @app.route("/my-reports")
    @login_required
    def my_reports():
        items = get_db().execute(
            "SELECT * FROM items WHERE owner_id = ? ORDER BY created_at DESC",
            (g.user["id"],),
        ).fetchall()
        return render_template("my_reports.html", items=items)

    @app.route("/items/<int:item_id>/contact", methods=["GET", "POST"])
    @login_required
    def contact_owner(item_id: int):
        item = item_by_id(item_id)
        if item["is_hidden"] or item["status"] == "returned":
            abort(404)
        if item["owner_id"] == g.user["id"]:
            flash("This is your report.", "info")
            return redirect(url_for("item_detail", item_id=item_id))
        if request.method == "POST":
            message = request.form.get("message", "").strip()
            if not 10 <= len(message) <= 1200:
                flash("Your message must be between 10 and 1,200 characters.", "error")
                return render_template("contact.html", item=item)
            get_db().execute(
                """
                INSERT INTO contact_requests (item_id, sender_id, recipient_id, message)
                VALUES (?, ?, ?, ?)
                """,
                (item_id, g.user["id"], item["owner_id"], message),
            )
            get_db().commit()
            flash("Your private contact request has been sent.", "success")
            return redirect(url_for("inbox"))
        return render_template("contact.html", item=item)

    @app.route("/inbox")
    @login_required
    def inbox():
        requests_received = get_db().execute(
            """
            SELECT contact_requests.*, items.title AS item_title,
                   users.full_name AS other_name
            FROM contact_requests
            JOIN items ON items.id = contact_requests.item_id
            JOIN users ON users.id = contact_requests.sender_id
            WHERE contact_requests.recipient_id = ?
            ORDER BY contact_requests.created_at DESC
            """,
            (g.user["id"],),
        ).fetchall()
        requests_sent = get_db().execute(
            """
            SELECT contact_requests.*, items.title AS item_title,
                   users.full_name AS other_name
            FROM contact_requests
            JOIN items ON items.id = contact_requests.item_id
            JOIN users ON users.id = contact_requests.recipient_id
            WHERE contact_requests.sender_id = ?
            ORDER BY contact_requests.created_at DESC
            """,
            (g.user["id"],),
        ).fetchall()
        return render_template(
            "inbox.html",
            requests_received=requests_received,
            requests_sent=requests_sent,
        )

    @app.route("/inbox/<int:contact_id>/reply", methods=["POST"])
    @login_required
    def reply_to_contact(contact_id: int):
        contact = get_db().execute(
            "SELECT * FROM contact_requests WHERE id = ?", (contact_id,)
        ).fetchone()
        if contact is None:
            abort(404)
        if contact["recipient_id"] != g.user["id"]:
            abort(403)
        reply = request.form.get("reply", "").strip()
        if not 10 <= len(reply) <= 1200:
            flash("Your reply must be between 10 and 1,200 characters.", "error")
        else:
            get_db().execute(
                """
                UPDATE contact_requests SET reply = ?, replied_at = CURRENT_TIMESTAMP
                WHERE id = ? AND recipient_id = ?
                """,
                (reply, contact_id, g.user["id"]),
            )
            get_db().commit()
            flash("Your private reply has been sent.", "success")
        return redirect(url_for("inbox"))

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        db = get_db()
        members = db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'student' AND is_active = 1"
        ).fetchone()[0]
        total_posts = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        lost_count = db.execute(
            "SELECT COUNT(*) FROM items WHERE kind = 'lost' AND status = 'active'"
        ).fetchone()[0]
        found_count = db.execute(
            "SELECT COUNT(*) FROM items WHERE status = 'found'"
        ).fetchone()[0]
        returned_count = db.execute(
            "SELECT COUNT(*) FROM items WHERE status = 'returned'"
        ).fetchone()[0]
        recent_activity = db.execute(
            """
            SELECT items.id, items.title, items.kind, items.status, items.created_at,
                   users.full_name
            FROM items JOIN users ON users.id = items.owner_id
            ORDER BY items.created_at DESC LIMIT 8
            """
        ).fetchall()
        needs_review = db.execute(
            "SELECT COUNT(*) FROM items WHERE is_hidden = 1"
        ).fetchone()[0]
        return render_template(
            "admin.html",
            members=members,
            total_posts=total_posts,
            lost_count=lost_count,
            found_count=found_count,
            returned_count=returned_count,
            recent_activity=recent_activity,
            needs_review=needs_review,
        )

    @app.route("/admin/posts", methods=["GET", "POST"])
    @admin_required
    def admin_posts():
        if request.method == "POST":
            item_id = request.form.get("item_id", type=int)
            action = request.form.get("action", "")
            item = get_db().execute(
                "SELECT id FROM items WHERE id = ?", (item_id,)
            ).fetchone()
            if item is None or action not in {"hide", "restore"}:
                abort(400, description="Invalid moderation action.")
            hidden = 1 if action == "hide" else 0
            get_db().execute(
                "UPDATE items SET is_hidden = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (hidden, item_id),
            )
            get_db().commit()
            flash("Post hidden from students." if hidden else "Post restored.", "success")
            return redirect(url_for("admin_posts"))
        posts = get_db().execute(
            """
            SELECT items.*, users.full_name AS owner_name, users.email AS owner_email
            FROM items JOIN users ON users.id = items.owner_id
            ORDER BY items.is_hidden DESC, items.created_at DESC LIMIT 100
            """
        ).fetchall()
        return render_template("admin_posts.html", posts=posts)

    @app.route("/admin/members", methods=["GET", "POST"])
    @admin_required
    def admin_members():
        if request.method == "POST":
            member_id = request.form.get("member_id", type=int)
            action = request.form.get("action", "")
            if member_id == g.user["id"]:
                flash("You cannot suspend your own administrator account.", "error")
                return redirect(url_for("admin_members"))
            member = get_db().execute(
                "SELECT id, role, is_active FROM users WHERE id = ?", (member_id,)
            ).fetchone()
            if member is None or member["role"] != "student" or action not in {
                "suspend",
                "restore",
            }:
                abort(400, description="Invalid account-management action.")
            is_active = 0 if action == "suspend" else 1
            get_db().execute(
                "UPDATE users SET is_active = ? WHERE id = ?", (is_active, member_id)
            )
            get_db().commit()
            flash(
                "Student account suspended." if not is_active else "Student account restored.",
                "success",
            )
            return redirect(url_for("admin_members"))
        members = get_db().execute(
            """
            SELECT id, full_name, email, is_active, created_at
            FROM users WHERE role = 'student' ORDER BY created_at DESC LIMIT 200
            """
        ).fetchall()
        return render_template("admin_members.html", members=members)

    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "error.html", code=400, message=getattr(error, "description", "Bad request.")
        ), 400

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template(
            "error.html",
            code=403,
            message="You do not have permission to view this page.",
        ), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html", code=404, message="We couldn't find that page or report."
        ), 404

    @app.errorhandler(413)
    def upload_too_large(_error):
        return render_template(
            "error.html", code=413, message="That upload is too large. The limit is 3 MB."
        ), 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
