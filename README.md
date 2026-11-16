# CampusFind

CampusFind is a beginner-friendly lost-and-found website for a college campus. It uses Python, Flask, SQLite, HTML, CSS, and a small amount of JavaScript. It does not need a paid service or an external database.

## Features

- Student registration, sign-in, and sign-out
- Lost and found reports with category, date, campus location, description, and optional image
- Home page sections for lost, found, and returned items, with keyword, category, and location filters
- A personal reports page to edit, delete, and update the status of your reports
- Private contact requests and replies; student email addresses are never shown on public reports
- Administrator dashboard with member and post counts, status chart, recent activity, moderation, and account suspension
- Password hashing, independent recovery-code password reset, form CSRF protection, role checks, image validation, and server-side validation

## Run on a laptop

1. Install Python 3.10 or newer (tested with Python 3.13).
2. Open a terminal in this `CampusFind-College-Submission` folder.
3. (Recommended) Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS / Linux:
   source .venv/bin/activate
   ```

4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Create the first administrator from the terminal (optional, only if needed):

   ```bash
   python create_admin.py
   ```

   Administrator accounts cannot be created from the public sign-up page. The setup command refuses to create a second administrator.

6. Start the website:

   ```bash
   python app.py
   ```

7. Open <http://127.0.0.1:5000> in your web browser.

The SQLite database is automatically created in `instance/campusfind.sqlite3` from `schema.sql` on first launch. Uploaded item images are stored in `static/uploads/`.

## Running the Automated Test Suite

To run all automated test cases using an isolated temporary database:

```bash
python run_tests.py
```
Or:
```bash
python -m unittest discover -s tests -v
```

## Password Recovery with Recovery Codes

Password recovery works independently using cryptographically secure recovery codes:

- **Upon Student Registration**: A cryptographically random 16-character recovery code (e.g. `CF9A-7B2X-4K8M-3P9W`) is generated and displayed once with a convenient "Copy Recovery Code" button.
- **Secure Storage**: CampusFind only stores a SHA-256 hash of the recovery code in the database. The plaintext code is never stored.
- **Forgot Password**: On `/forgot-password`, students enter their college email, their recovery code, and choose a new password.
- **Single-Use Invalidation**: Once used to successfully reset a password, the recovery code is permanently invalidated and cannot be reused.
- **Brute-Force Protection**: 5 consecutive incorrect code entries lock password recovery for 15 minutes to prevent automated guessing.
- **Account Security for Existing Users**: Logged-in students can view their recovery status and generate a replacement code anytime under **Security** (`/account/recovery-code`) by verifying their current password. Generating a replacement immediately invalidates the previous code.
- **Running Tests**: Run the automated test suite with:

   ```bash
   python -m unittest discover -s tests -v
   ```

## Replit

The project starts with the configured CampusFind run command. To create the first administrator, open the Shell, run `cd campusfind && python create_admin.py`, and follow the prompts. Register student accounts from the website.

## Safety and demo notes

- Public registration always creates a student account; the role is assigned on the server.
- Private contact requests are visible only to the sender and recipient. The item owner's email is not included on public pages.
- The embedded Replit preview uses a secure, partitioned cross-site session cookie so registration forms retain their session. Local laptop runs default to the first-party `Lax` cookie setting.
- For an HTTPS-hosted copy, set `COOKIE_SECURE=1` and provide a long random `SESSION_SECRET` in the environment.
- This is a college-project starter, not a substitute for a security review before handling real student data.
