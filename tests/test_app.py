"""Small end-to-end checks for the beginner demo."""

import io
import os
import re
import hashlib
import tempfile
import unittest
from datetime import date
from pathlib import Path

from werkzeug.security import generate_password_hash

from app import create_app, hash_recovery_code, normalize_recovery_code
from database import get_db


class CampusFindTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-session-key",
                "DATABASE": str(root / "test.sqlite3"),
                "UPLOAD_FOLDER": str(root / "uploads"),
                "SESSION_COOKIE_SECURE": False,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf(self, client=None):
        client = client or self.client
        with client.session_transaction() as session:
            session["_csrf_token"] = "test-csrf-token"
        return "test-csrf-token"

    def register(self, email, name, client=None, password="safe-student-password", extra=None):
        client = client or self.client
        data = {
            "csrf_token": self.csrf(client),
            "full_name": name,
            "email": email,
            "password": password,
        }
        if extra:
            data.update(extra)
        return client.post("/register", data=data, follow_redirects=True)

    def login(self, email, password, client=None):
        client = client or self.client
        return client.post(
            "/login",
            data={
                "csrf_token": self.csrf(client),
                "email": email,
                "password": password,
            },
            follow_redirects=True,
        )

    def extract_recovery_code(self, response_data: bytes) -> str:
        """Extract the 16-character recovery code displayed on the recovery_code.html page."""
        match = re.search(r'id="recoveryCodeBox"[^>]*>\s*([A-Za-z0-9\-]+)\s*<', response_data.decode("utf-8"))
        self.assertIsNotNone(match, "Recovery code should be visible on recovery_code.html")
        return match.group(1).strip()

    def recover_password(self, email, recovery_code, new_password, confirm_password=None, client=None):
        client = client or self.app.test_client()
        return client.post(
            "/forgot-password",
            data={
                "csrf_token": self.csrf(client),
                "email": email,
                "recovery_code": recovery_code,
                "password": new_password,
                "confirm_password": new_password if confirm_password is None else confirm_password,
            },
            follow_redirects=False,
        )

    def create_report(self, client=None, kind="found", title="Blue water bottle"):
        client = client or self.client
        return client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(client),
                "kind": kind,
                "title": title,
                "description": "Found near the library stairs this morning.",
                "category": "Other",
                "location": "Central Library",
                "item_date": date.today().isoformat(),
            },
        )

    def test_registration_session_round_trip_then_login(self):
        response = self.register("student@college.edu", "Taylor Student")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Save Your Recovery Code", response.data)
        self.assertIn(b"Taylor", response.data)

        logout = self.client.post(
            "/logout",
            data={"csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertEqual(logout.status_code, 200)
        self.assertIn(b"You have been signed out", logout.data)

        login = self.login("student@college.edu", "safe-student-password")
        self.assertEqual(login.status_code, 200)
        self.assertIn(b"Welcome back, Taylor", login.data)

    def test_registration_with_new_gmail_address_succeeds(self):
        gmail_client = self.app.test_client()
        response = self.register(
            "student.test.campus@gmail.com",
            "Jordan Campus",
            client=gmail_client,
            password="safe-secure-password-123",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Save Your Recovery Code", response.data)
        self.assertIn(b"Jordan", response.data)
        code = self.extract_recovery_code(response.data)
        self.assertEqual(len(normalize_recovery_code(code)), 16)

        # Verify user is in database
        with self.app.app_context():
            user = get_db().execute(
                "SELECT id, full_name, email FROM users WHERE email = 'student.test.campus@gmail.com'"
            ).fetchone()
            self.assertIsNotNone(user)
            self.assertEqual(user["full_name"], "Jordan Campus")

    def test_registration_rejects_genuinely_duplicate_email_case_insensitively(self):
        self.register("original@gmail.com", "Original Student")
        
        # Second registration with identical email (different case)
        other_client = self.app.test_client()
        dup_response = self.register(
            "ORIGINAL@GMAIL.COM",
            "Duplicate Student",
            client=other_client,
            password="another-password-123",
        )
        self.assertEqual(dup_response.status_code, 200)
        self.assertIn(b"An account with that email already exists", dup_response.data)

        # Ensure only 1 account exists in database
        with self.app.app_context():
            count = get_db().execute(
                "SELECT COUNT(*) FROM users WHERE email = 'original@gmail.com' COLLATE NOCASE"
            ).fetchone()[0]
            self.assertEqual(count, 1)

    def test_registration_generates_recovery_code_and_displays_once(self):
        reg = self.register("alex@college.edu", "Alex Rivera")
        self.assertEqual(reg.status_code, 200)
        code = self.extract_recovery_code(reg.data)
        self.assertTrue(len(normalize_recovery_code(code)) == 16)
        self.assertIn(b"Copy Recovery Code", reg.data)
        self.assertIn(b"this recovery code is only shown once right now", reg.data)

        # Refreshing /recovery-code should no longer show the code (one-time display)
        second_view = self.client.get("/recovery-code", follow_redirects=True)
        self.assertNotIn(code.encode(), second_view.data)
        self.assertIn(b"recovery codes can only be displayed once", second_view.data)

    def test_recovery_code_is_hashed_and_not_stored_in_plaintext(self):
        reg = self.register("morgan@college.edu", "Morgan Lee")
        code = self.extract_recovery_code(reg.data)
        expected_hash = hash_recovery_code(code)

        with self.app.app_context():
            row = get_db().execute(
                """
                SELECT users.email, recovery_codes.code_hash, recovery_codes.failed_attempts
                FROM recovery_codes JOIN users ON users.id = recovery_codes.user_id
                WHERE users.email = ?
                """,
                ("morgan@college.edu",),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["code_hash"], expected_hash)
            self.assertNotEqual(row["code_hash"], code)
            self.assertEqual(row["failed_attempts"], 0)

    def test_successful_recovery_with_code_resets_password_and_is_single_use(self):
        # 1. Register and create a report to test data preservation
        reg = self.register("owner@college.edu", "Riley Owner")
        code = self.extract_recovery_code(reg.data)
        report = self.create_report(title="Preserved Laptop Charger")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        # 2. Reset password using recovery code
        anon = self.app.test_client()
        reset_resp = self.recover_password("owner@college.edu", code, "brand-new-safe-pass", client=anon)
        self.assertEqual(reset_resp.status_code, 302)
        self.assertEqual(reset_resp.headers["Location"], "/login")

        # 3. Old password must fail; new password must succeed
        fail_login = self.login("owner@college.edu", "safe-student-password", anon)
        self.assertIn(b"Email or password is incorrect", fail_login.data)

        success_login = self.login("owner@college.edu", "brand-new-safe-pass", anon)
        self.assertIn(b"Welcome back, Riley", success_login.data)

        # 4. Code cannot be reused (single-use invalidation)
        reuse_anon = self.app.test_client()
        reuse_resp = self.recover_password("owner@college.edu", code, "attempt-reuse-pass", client=reuse_anon)
        self.assertEqual(reuse_resp.status_code, 200)
        self.assertIn(b"No recovery code is registered for this account", reuse_resp.data)

        # 5. Data preservation verified: user and item still exist
        with self.app.app_context():
            item = get_db().execute("SELECT title FROM items WHERE id = ?", (item_id,)).fetchone()
            self.assertIsNotNone(item)
            self.assertEqual(item["title"], "Preserved Laptop Charger")

    def test_recovery_fails_with_invalid_code_or_mismatched_password(self):
        reg = self.register("testuser@college.edu", "Test Student")
        code = self.extract_recovery_code(reg.data)

        anon = self.app.test_client()

        # Password mismatch
        mismatch = self.recover_password(
            "testuser@college.edu", code, "new-pass-1234", "different-pass", client=anon
        )
        self.assertEqual(mismatch.status_code, 200)
        self.assertIn(b"passwords do not match", mismatch.data)

        # Invalid recovery code
        bad_code = self.recover_password(
            "testuser@college.edu", "WRONG-CODE-0000", "new-pass-1234", client=anon
        )
        self.assertEqual(bad_code.status_code, 200)
        self.assertIn(b"Invalid recovery code", bad_code.data)

    def test_recovery_code_rate_limiting_locks_after_5_failed_attempts(self):
        reg = self.register("locked@college.edu", "Lockout Student")
        correct_code = self.extract_recovery_code(reg.data)

        anon = self.app.test_client()

        # 4 failed attempts
        for attempt in range(1, 5):
            resp = self.recover_password("locked@college.edu", f"BAD-CODE-{attempt}", "pass123456", client=anon)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid recovery code", resp.data)

        # 5th failed attempt should trigger 15-minute lockout
        resp5 = self.recover_password("locked@college.edu", "BAD-CODE-5", "pass123456", client=anon)
        self.assertEqual(resp5.status_code, 200)
        self.assertIn(b"locked for 15 minutes", resp5.data)

        # Even if correct code is entered now, it is locked out
        resp_blocked = self.recover_password("locked@college.edu", correct_code, "pass123456", client=anon)
        self.assertEqual(resp_blocked.status_code, 200)
        self.assertIn(b"temporarily locked", resp_blocked.data)

    def test_logged_in_user_can_generate_replacement_recovery_code(self):
        reg = self.register("replace@college.edu", "Replace Student")
        initial_code = self.extract_recovery_code(reg.data)

        # User wants to cycle their code from /account/recovery-code
        # Wrong password fails
        bad_post = self.client.post(
            "/account/recovery-code",
            data={"csrf_token": self.csrf(), "current_password": "wrong-password"},
            follow_redirects=True,
        )
        self.assertIn(b"Current password is incorrect", bad_post.data)

        # Correct password generates new code
        good_post = self.client.post(
            "/account/recovery-code",
            data={"csrf_token": self.csrf(), "current_password": "safe-student-password"},
            follow_redirects=True,
        )
        self.assertEqual(good_post.status_code, 200)
        new_code = self.extract_recovery_code(good_post.data)
        self.assertNotEqual(initial_code, new_code)

        # Old code is invalidated; new code works for reset
        anon = self.app.test_client()
        old_attempt = self.recover_password("replace@college.edu", initial_code, "brand-new-pass", client=anon)
        self.assertIn(b"Invalid recovery code", old_attempt.data)

        new_attempt = self.recover_password("replace@college.edu", new_code, "brand-new-pass", client=anon)
        self.assertEqual(new_attempt.status_code, 302)

    def test_existing_user_without_code_can_safely_generate_first_code(self):
        # Simulate an existing user from prior to recovery-code feature
        with self.app.app_context():
            get_db().execute(
                """
                INSERT INTO users (full_name, email, password_hash, role)
                VALUES ('Legacy Student', 'legacy@college.edu', ?, 'student')
                """,
                (generate_password_hash("legacy-pass-123"),),
            )
            get_db().commit()

        legacy_client = self.app.test_client()
        self.login("legacy@college.edu", "legacy-pass-123", legacy_client)

        # Page tells them they don't have a code yet
        sec_page = legacy_client.get("/account/recovery-code")
        self.assertIn(b"No Recovery Code Found", sec_page.data)

        # Generate their first code
        gen_resp = legacy_client.post(
            "/account/recovery-code",
            data={"csrf_token": self.csrf(legacy_client), "current_password": "legacy-pass-123"},
            follow_redirects=True,
        )
        self.assertEqual(gen_resp.status_code, 200)
        first_code = self.extract_recovery_code(gen_resp.data)
        self.assertTrue(len(normalize_recovery_code(first_code)) == 16)

    def test_student_can_report_and_search_an_item(self):
        self.register("student@college.edu", "Student Example")
        response = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "lost",
                "title": "Black wireless headphones",
                "description": "Left behind in the second-floor computer lab near desk 14.",
                "category": "Electronics",
                "location": "Science Library",
                "item_date": date.today().isoformat(),
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Black wireless headphones", response.data)

        search_match = self.client.get("/?q=headphones")
        self.assertIn(b"Black wireless headphones", search_match.data)

        search_miss = self.client.get("/?q=umbrella")
        self.assertNotIn(b"Black wireless headphones", search_miss.data)

    def test_report_status_moves_from_lost_to_found_to_returned(self):
        self.register("owner@college.edu", "Riley Owner")
        report = self.create_report(kind="lost", title="Green notebook")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        for expected_status in ("found", "returned"):
            response = self.client.post(
                f"/items/{item_id}/status",
                data={"csrf_token": self.csrf()},
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            with self.app.app_context():
                item = get_db().execute(
                    "SELECT status FROM items WHERE id = ?", (item_id,)
                ).fetchone()
            self.assertEqual(item["status"], expected_status)

        self.assertIn(b"Green notebook", self.client.get("/").data)

    def test_contact_requests_are_private_between_students(self):
        self.register("owner@college.edu", "Riley Owner")
        report = self.create_report()
        item_id = report.headers["Location"].rsplit("/", 1)[-1]

        other = self.app.test_client()
        self.register("visitor@college.edu", "Sam Visitor", other)
        response = other.post(
            f"/items/{item_id}/contact",
            data={
                "csrf_token": self.csrf(other),
                "message": "I think this may be mine; I can describe the sticker.",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"private contact request has been sent", response.data)

        inbox = self.client.get("/inbox")
        self.assertIn(b"I think this may be mine", inbox.data)
        reply = self.client.post(
            "/inbox/1/reply",
            data={
                "csrf_token": self.csrf(),
                "reply": "Thanks for getting in touch. Please describe the sticker.",
            },
            follow_redirects=True,
        )
        self.assertIn(b"private reply has been sent", reply.data)
        self.assertIn(b"Please describe the sticker", other.get("/inbox").data)

    def test_admin_routes_are_restricted_and_posts_can_be_moderated(self):
        self.register("student@college.edu", "Student Example")
        report = self.create_report(kind="lost", title="Lost notebook")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])
        self.assertEqual(self.client.get("/admin").status_code, 403)

        with self.app.app_context():
            get_db().execute(
                """
                INSERT INTO users (full_name, email, password_hash, role)
                VALUES (?, ?, ?, 'admin')
                """,
                (
                    "Campus Admin",
                    "admin@college.edu",
                    generate_password_hash("safe-admin-password"),
                ),
            )
            get_db().commit()

        admin = self.app.test_client()
        self.login("admin@college.edu", "safe-admin-password", admin)
        self.assertEqual(admin.get("/admin").status_code, 200)
        response = admin.post(
            "/admin/posts",
            data={
                "csrf_token": self.csrf(admin),
                "item_id": str(item_id),
                "action": "hide",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Post hidden from students", response.data)
        visitor = self.app.test_client()
        self.assertEqual(visitor.get(f"/items/{item_id}").status_code, 404)

    def test_csrf_rejects_a_post_without_the_session_cookie(self):
        client = self.app.test_client(use_cookies=False)
        page = client.get("/register")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(token)
        response = client.post(
            "/register",
            data={
                "csrf_token": token.group(1).decode(),
                "full_name": "No Cookie",
                "email": "nocookie@college.edu",
                "password": "correct-horse-battery",
            },
        )
        self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            user = get_db().execute(
                "SELECT id FROM users WHERE email = ?", ("nocookie@college.edu",)
            ).fetchone()
        self.assertIsNone(user)

    def test_csrf_is_required_and_users_cannot_edit_another_students_report(self):
        self.register("first@college.edu", "First Student")
        report = self.create_report()
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        second = self.app.test_client()
        self.register("second@college.edu", "Second Student", second)
        self.assertEqual(second.get(f"/items/{item_id}/edit").status_code, 403)
        no_token = self.client.post("/logout", data={})
        self.assertEqual(no_token.status_code, 400)

    def test_login_page_links_to_forgot_password(self):
        page = self.client.get("/login")
        self.assertIn(b"/forgot-password", page.data)

    def test_promoted_account_retains_student_features_and_gains_admin_access_and_recovery(self):
        # 1. Register as a normal student
        reg = self.register("dual@college.edu", "Dual Role Student")
        self.assertEqual(reg.status_code, 200)
        code = self.extract_recovery_code(reg.data)

        # 2. Post a report as a student
        report = self.create_report(kind="lost", title="Dual Student Lost Calculator")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        # 3. Promote account to admin in database
        with self.app.app_context():
            get_db().execute(
                "UPDATE users SET role = 'admin' WHERE email = 'dual@college.edu'"
            )
            get_db().commit()

        # 4. Student feature 1: View My Reports
        my_reports = self.client.get("/my-reports")
        self.assertEqual(my_reports.status_code, 200)
        self.assertIn(b"Dual Student Lost Calculator", my_reports.data)

        # 5. Student feature 2: Update report status
        status_resp = self.client.post(
            f"/items/{item_id}/status",
            data={"csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertEqual(status_resp.status_code, 200)
        self.assertIn(b"Marked as found", status_resp.data)

        # 6. Admin feature: Access Admin Dashboard & Post Moderation
        admin_page = self.client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn(b"Live campus overview", admin_page.data)

        admin_posts = self.client.get("/admin/posts")
        self.assertEqual(admin_posts.status_code, 200)
        self.assertIn(b"Post moderation", admin_posts.data)

        # 7. Password Recovery feature: Admin can recover password using recovery code
        anon = self.app.test_client()
        recovery_resp = self.recover_password(
            "dual@college.edu", code, "new-secure-dual-password", client=anon
        )
        self.assertEqual(recovery_resp.status_code, 302)
        self.assertEqual(recovery_resp.headers["Location"], "/login")

        # 8. Sign in with the new password
        new_login = self.login("dual@college.edu", "new-secure-dual-password", anon)
        self.assertEqual(new_login.status_code, 200)
        self.assertIn(b"Welcome back, Dual", new_login.data)

    def test_registration_input_validation_and_authenticated_redirect(self):
        # 1. Short name (< 2 characters)
        short_name = self.register("shortname@college.edu", "A")
        self.assertEqual(short_name.status_code, 200)
        self.assertIn(b"Your name must be between 2 and 80 characters", short_name.data)

        # 2. Invalid email format
        bad_email = self.register("notanemail", "Valid Name")
        self.assertEqual(bad_email.status_code, 200)
        self.assertIn(b"Enter a valid email address", bad_email.data)

        # 3. Short password (< 8 characters)
        short_pass = self.register("shortpass@college.edu", "Valid Name", password="short")
        self.assertEqual(short_pass.status_code, 200)
        self.assertIn(b"Your password must be between 8 and 128 characters", short_pass.data)

        # 4. Authenticated user visiting /register redirects to home
        self.register("auth@college.edu", "Auth Student")
        auth_visit = self.client.get("/register")
        self.assertEqual(auth_visit.status_code, 302)
        self.assertEqual(auth_visit.headers["Location"], "/")

    def test_login_failure_modes_and_suspended_account(self):
        # 1. Non-existent user login
        anon = self.app.test_client()
        missing_user = self.login("ghost@college.edu", "anypassword123", anon)
        self.assertEqual(missing_user.status_code, 200)
        self.assertIn(b"Email or password is incorrect", missing_user.data)

        # 2. Existing user, incorrect password
        self.register("existing@college.edu", "Existing Student")
        bad_pwd = self.login("existing@college.edu", "wrong-password", anon)
        self.assertEqual(bad_pwd.status_code, 200)
        self.assertIn(b"Email or password is incorrect", bad_pwd.data)

        # 3. Suspended / inactive account (is_active = 0)
        with self.app.app_context():
            get_db().execute("UPDATE users SET is_active = 0 WHERE email = 'existing@college.edu'")
            get_db().commit()
        suspended_login = self.login("existing@college.edu", "safe-student-password", anon)
        self.assertEqual(suspended_login.status_code, 200)
        self.assertIn(b"Email or password is incorrect", suspended_login.data)

        # 4. Authenticated user visiting /login redirects to home
        auth_client = self.app.test_client()
        self.register("activeuser@college.edu", "Active Student", client=auth_client)
        auth_visit = auth_client.get("/login")
        self.assertEqual(auth_visit.status_code, 302)
        self.assertEqual(auth_visit.headers["Location"], "/")

    def test_item_form_validation_and_missing_item_errors(self):
        self.register("poster@college.edu", "Poster Student")

        # 1. Title too short (< 3 chars)
        bad_title = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "lost",
                "title": "AB",
                "description": "Lost my keys near the courtyard this morning.",
                "category": "Keys",
                "location": "Courtyard",
                "item_date": date.today().isoformat(),
            },
            follow_redirects=True,
        )
        self.assertEqual(bad_title.status_code, 200)
        self.assertIn(b"title must be between 3 and 100 characters", bad_title.data)

        # 2. Invalid category (not in CATEGORIES)
        bad_cat = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "lost",
                "title": "Lost Wallet",
                "description": "Lost near the cafeteria tables.",
                "category": "InvalidCategory123",
                "location": "Cafeteria",
                "item_date": date.today().isoformat(),
            },
            follow_redirects=True,
        )
        self.assertEqual(bad_cat.status_code, 200)
        self.assertIn(b"Choose a category from the list", bad_cat.data)

        # 3. Future date rejected
        bad_date = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "lost",
                "title": "Lost Glasses",
                "description": "Lost near the reading hall.",
                "category": "Other",
                "location": "Reading Hall",
                "item_date": "2099-01-01",
            },
            follow_redirects=True,
        )
        self.assertEqual(bad_date.status_code, 200)
        self.assertIn(b"date cannot be in the future", bad_date.data)

        # 4. Non-existent item ID returns 404
        self.assertEqual(self.client.get("/items/999999").status_code, 404)

        # 5. Student privacy check: owner email is NOT exposed on item detail
        valid_rep = self.create_report(title="Public Lost Item")
        rep_id = int(valid_rep.headers["Location"].rsplit("/", 1)[-1])
        detail = self.client.get(f"/items/{rep_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertNotIn(b"poster@college.edu", detail.data)
        self.assertIn(b"Campus member", detail.data)

    def test_item_edit_and_delete_permissions(self):
        self.register("author@college.edu", "Author Student")
        report = self.create_report(title="Original Report Title")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        # 1. Author can edit report details
        edit_resp = self.client.post(
            f"/items/{item_id}/edit",
            data={
                "csrf_token": self.csrf(),
                "kind": "found",
                "title": "Updated Report Title",
                "description": "Found near the main lobby entrance.",
                "category": "Books",
                "location": "Main Lobby",
                "item_date": date.today().isoformat(),
            },
            follow_redirects=True,
        )
        self.assertEqual(edit_resp.status_code, 200)
        self.assertIn(b"Your report has been updated", edit_resp.data)
        self.assertIn(b"Updated Report Title", edit_resp.data)

        # 2. Other student attempting to delete report gets 403 Forbidden
        other = self.app.test_client()
        self.register("other@college.edu", "Other Student", client=other)
        unauth_del = other.post(f"/items/{item_id}/delete", data={"csrf_token": self.csrf(other)})
        self.assertEqual(unauth_del.status_code, 403)

        # 3. Author can delete report
        del_resp = self.client.post(
            f"/items/{item_id}/delete",
            data={"csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertIn(b"report has been deleted", del_resp.data)
        self.assertEqual(self.client.get(f"/items/{item_id}").status_code, 404)

    def test_item_status_returned_cannot_be_changed(self):
        self.register("lifecycle@college.edu", "Lifecycle Student")
        report = self.create_report(kind="lost", title="Lifecycle Calculator")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        # Lost -> Found
        self.client.post(f"/items/{item_id}/status", data={"csrf_token": self.csrf()}, follow_redirects=True)
        # Found -> Returned
        self.client.post(f"/items/{item_id}/status", data={"csrf_token": self.csrf()}, follow_redirects=True)

        # Updating when already 'returned' must abort with 400
        invalid_next = self.client.post(
            f"/items/{item_id}/status",
            data={"csrf_token": self.csrf()},
        )
        self.assertEqual(invalid_next.status_code, 400)

        # Non-owner attempting status change gets 403
        stranger = self.app.test_client()
        self.register("stranger@college.edu", "Stranger Student", client=stranger)
        stranger_resp = stranger.post(f"/items/{item_id}/status", data={"csrf_token": self.csrf(stranger)})
        self.assertEqual(stranger_resp.status_code, 403)

    def test_image_upload_magic_bytes_validation(self):
        Path(self.app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
        self.register("photographer@college.edu", "Photo Student")

        # 1. Valid PNG upload with correct magic header
        valid_png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 30
        valid_upload = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "found",
                "title": "Umbrella with Photo",
                "description": "Found a red umbrella near entrance.",
                "category": "Other",
                "location": "North Entrance",
                "item_date": date.today().isoformat(),
                "image": (io.BytesIO(valid_png_content), "umbrella.png"),
            },
            follow_redirects=False,
        )
        self.assertEqual(valid_upload.status_code, 302)
        uploaded_id = int(valid_upload.headers["Location"].rsplit("/", 1)[-1])

        with self.app.app_context():
            item_row = get_db().execute("SELECT image_filename FROM items WHERE id = ?", (uploaded_id,)).fetchone()
            self.assertIsNotNone(item_row["image_filename"])
            self.assertTrue(item_row["image_filename"].endswith(".png"))
            # File physically written to upload directory
            img_file = Path(self.app.config["UPLOAD_FOLDER"]) / item_row["image_filename"]
            self.assertTrue(img_file.is_file())

        # 2. Fake PNG (corrupted / text file disguised as PNG)
        fake_upload = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "found",
                "title": "Disguised File",
                "description": "Attempting to bypass file type check.",
                "category": "Other",
                "location": "North Entrance",
                "item_date": date.today().isoformat(),
                "image": (io.BytesIO(b"Not a real png file content"), "fake.png"),
            },
            follow_redirects=True,
        )
        self.assertEqual(fake_upload.status_code, 200)
        self.assertIn(b"not a supported image", fake_upload.data)

        # 3. Disallowed extension (.exe or .pdf)
        bad_ext = self.client.post(
            "/items/new",
            data={
                "csrf_token": self.csrf(),
                "kind": "found",
                "title": "Executable File",
                "description": "Attempting to upload executable.",
                "category": "Other",
                "location": "North Entrance",
                "item_date": date.today().isoformat(),
                "image": (io.BytesIO(b"executable payload"), "payload.exe"),
            },
            follow_redirects=True,
        )
        self.assertEqual(bad_ext.status_code, 200)
        self.assertIn(b"Choose a JPG, PNG, or WebP image", bad_ext.data)

    def test_contact_request_edge_cases_and_privacy(self):
        self.register("itemowner@college.edu", "Item Owner")
        report = self.create_report(title="Owner Flash Drive")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        # 1. Student attempting to send contact request to their own item is blocked
        self_contact = self.client.post(
            f"/items/{item_id}/contact",
            data={"csrf_token": self.csrf(), "message": "Trying to contact myself."},
            follow_redirects=True,
        )
        self.assertIn(b"This is your report", self_contact.data)

        # 2. Message too short (< 10 characters)
        sender = self.app.test_client()
        self.register("inquiring@college.edu", "Inquiring Student", client=sender)
        short_msg = sender.post(
            f"/items/{item_id}/contact",
            data={"csrf_token": self.csrf(sender), "message": "Hi!"},
            follow_redirects=True,
        )
        self.assertIn(b"must be between 10 and 1,200 characters", short_msg.data)

        # 3. Contacting a returned item returns 404
        self.client.post(f"/items/{item_id}/status", data={"csrf_token": self.csrf()})
        self.client.post(f"/items/{item_id}/status", data={"csrf_token": self.csrf()})
        self.assertEqual(sender.get(f"/items/{item_id}/contact").status_code, 404)

    def test_admin_member_management_and_self_suspension_protection(self):
        # 1. Register student
        self.register("troublemaker@college.edu", "Troublemaker Student")
        with self.app.app_context():
            student = get_db().execute("SELECT id FROM users WHERE email = 'troublemaker@college.edu'").fetchone()
            student_id = student["id"]

        # 2. Non-admin accessing /admin/members receives 403 Forbidden
        self.assertEqual(self.client.get("/admin/members").status_code, 403)

        # 3. Create and login administrator
        with self.app.app_context():
            get_db().execute(
                "INSERT INTO users (full_name, email, password_hash, role) VALUES ('Admin User', 'headadmin@college.edu', ?, 'admin')",
                (generate_password_hash("admin-pass-1234"),),
            )
            get_db().commit()

        admin_client = self.app.test_client()
        self.login("headadmin@college.edu", "admin-pass-1234", client=admin_client)

        # Admin access to /admin/members
        mem_page = admin_client.get("/admin/members")
        self.assertEqual(mem_page.status_code, 200)
        self.assertIn(b"Troublemaker Student", mem_page.data)

        # 4. Admin suspends the student account
        suspend_resp = admin_client.post(
            "/admin/members",
            data={"csrf_token": self.csrf(admin_client), "member_id": student_id, "action": "suspend"},
            follow_redirects=True,
        )
        self.assertEqual(suspend_resp.status_code, 200)
        self.assertIn(b"Student account suspended", suspend_resp.data)

        with self.app.app_context():
            is_act = get_db().execute("SELECT is_active FROM users WHERE id = ?", (student_id,)).fetchone()["is_active"]
            self.assertEqual(is_act, 0)

        # 5. Admin restores the student account
        restore_resp = admin_client.post(
            "/admin/members",
            data={"csrf_token": self.csrf(admin_client), "member_id": student_id, "action": "restore"},
            follow_redirects=True,
        )
        self.assertEqual(restore_resp.status_code, 200)
        self.assertIn(b"Student account restored", restore_resp.data)

        with self.app.app_context():
            is_act_restored = get_db().execute("SELECT is_active FROM users WHERE id = ?", (student_id,)).fetchone()["is_active"]
            self.assertEqual(is_act_restored, 1)

        # 6. Admin cannot suspend themselves
        with self.app.app_context():
            admin_id = get_db().execute("SELECT id FROM users WHERE email = 'headadmin@college.edu'").fetchone()["id"]
        self_susp = admin_client.post(
            "/admin/members",
            data={"csrf_token": self.csrf(admin_client), "member_id": admin_id, "action": "suspend"},
            follow_redirects=True,
        )
        self.assertIn(b"cannot suspend your own administrator account", self_susp.data)

    def test_database_foreign_key_cascade_deletions(self):
        # 1. Register student, post report, send contact request
        self.register("cascade1@college.edu", "Cascade Owner")
        report = self.create_report(title="Cascade Item")
        item_id = int(report.headers["Location"].rsplit("/", 1)[-1])

        sender = self.app.test_client()
        self.register("cascade2@college.edu", "Cascade Sender", client=sender)
        sender.post(
            f"/items/{item_id}/contact",
            data={"csrf_token": self.csrf(sender), "message": "Cascading message test."},
        )

        with self.app.app_context():
            db = get_db()
            cr_count = db.execute("SELECT COUNT(*) FROM contact_requests WHERE item_id = ?", (item_id,)).fetchone()[0]
            self.assertEqual(cr_count, 1)

            # Deleting item must automatically cascade and delete its contact requests
            db.execute("DELETE FROM items WHERE id = ?", (item_id,))
            db.commit()

            cr_after = db.execute("SELECT COUNT(*) FROM contact_requests WHERE item_id = ?", (item_id,)).fetchone()[0]
            self.assertEqual(cr_after, 0)

            # Deleting user must cascade and delete their items, contact requests, and recovery codes
            user1_id = db.execute("SELECT id FROM users WHERE email = 'cascade1@college.edu'").fetchone()["id"]
            db.execute("DELETE FROM users WHERE id = ?", (user1_id,))
            db.commit()

            rc_count = db.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?", (user1_id,)).fetchone()[0]
            self.assertEqual(rc_count, 0)


if __name__ == "__main__":
    unittest.main()
