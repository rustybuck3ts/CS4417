
## Architecture & Technologies
- **Backend Framework**: Flask
- **Database**: SQLite3 (using parameterization for SQL injection prevention)
- **Password Hashing**: `bcrypt`
- **Security Extensions**: `Flask-WTF` (for CSRF protection), `MarkupSafe` (for XSS sanitization)
- **Testing**: `pytest`

## Application Features
1. **User Authentication**: Secure registration and login flows. Passwords are mathematically hashed with salts. Session identifiers are regenerated upon login.
2. **Role-based Access Control (RBAC)**: Supports `user` and `admin` roles. Admins have access to an administrative dashboard for moderating content and managing users.
3. **Feedback System**: Authenticated users can submit feedback. Feedback is safely escaped to prevent stored XSS attacks.
4. **Self-Service Password Management**: Logged-in users can safely change their own passwords.
5. **Administrative Controls**: Admins can view all users, delete users, delete feedback, change passwords on behalf of other users, and promote standard users to admins.

---

## File Directory Breakdown

### 1. `app.py`
The main entry point and routing controller for the Flask application. 
- Initializes the Flask application with a strong cryptographically secure random secret key.
- Enables global CSRF protection using `Flask-WTF`.
- Defines all web routes:
  - `/` (Index): The main dashboard, showing recent feedback and the password change utility.
  - `/register`, `/login`, `/logout`: Authentication routes.
  - `/feedback`: Allows authenticated users to submit feedback. Protects against XSS by passing input through `escape()`.
  - `/admin`: Renders the admin dashboard, protected by an RBAC check against the session role.
  - `/admin/delete_user`, `/admin/delete_feedback`, `/admin/promote_user`: Admin-only action routes.
  - `/change_password/<user_id>`: Password change function for both standard users (self-service) and admins (override).
- Handles server startup and initial database seeding.

### 2. `database.py`
The data access layer handling all SQLite3 interactions.
- `init_db()`: Reads `schema.sql` to initialize the database structure.
- `create_user()`, `verify_user()`: Handles secure user registration and login. Incorporates the `bcrypt` library to salt and hash passwords.
- `insert_feedback()`, `get_all_feedback()`: SQL functions for the feedback table. Note that queries use parameterized `(?, ?)` bindings to eliminate SQL Injection (SQLi) vulnerabilities.
- `get_all_users()`, `delete_user()`, `promote_user()`, `change_password()`: Administrative and utility user management queries.

### 3. `schema.sql`
The database schema definition script.
- Defines the `users` table including `id`, `username`, `password_hash`, and checking for a `role` default set to `user`.
- Defines the `feedback` table linking messages to users via a foreign key `user_id`.

### 4. `test_app.py`
The automated testing suite utilizing `pytest`.
- Creates a temporary SQLite database for test isolation.
- `test_register_and_login()`: Validates the core authentication pipeline.
- `test_sql_injection_login()`: Attempts to bypass authentication using a known SQLi payload (`' OR '1'='1`) and asserts that the login correctly fails.
- `test_xss_protection_feedback()`: Submits HTML/JavaScript `<script>` tags as feedback and asserts the output is safely escaped (`&lt;script&gt;`) instead of rendering raw HTML.
- `test_change_password()`: Tests that a standard user can successfully rotate their password and log back in.
- `test_admin_promote_and_change_user_password()`: Verifies that an admin can promote accounts and override user passwords.

### 5. `requirements.txt`
Declares the Python dependencies required to run the application (`Flask`, `bcrypt`, `pytest`, `Flask-WTF`).

---

## The Presentation Layer (`/templates`)
The frontend uses Jinja2 templates extending a common base layout.

### `base.html`
The parent layout for the entire application.
- Contains the HTML head, global CSS styling, the navigation header, and a block for displaying Flask "flash" messages (errors/success states).
- Dynamically displays navigation links (e.g. Admin Dashboard, Login vs Logout) depending on the user's current session state.

### `index.html`
The main landing page for authenticated users.
- Welcomes the user and presents a form letting them change their own password.
- Displays a river of all submitted feedback from other users.

### `login.html` & `register.html`
Simple credential entry forms. They include a hidden CSRF token (`csrf_token()`) to ensure the submission originated from the legitimate web application.

### `feedback.html`
A form with a `textarea` for users to submit feedback to the database.

### `admin.html`
The administrative control panel.
- Shows a data table of all users with inline buttons to **Promote**, **Change PW**, or **Delete**.
- Shows a data table of all system feedback logs with an inline **Remove** button.
- Includes confirmation dialogs before running destructive operations like deletion.
