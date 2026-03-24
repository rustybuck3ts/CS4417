# Secure Software Architecture and Design

This document covers the security features, design choices, and architectural vulnerability assessment of our application.

## 1. Secure Architecture and Design Principles

The application implements several core security principles to protect against common web vulnerabilities (e.g., OWASP Top 10).

### Authentication & Session Management
- **Password Hashes & Salting**: Passwords are never stored in plaintext. The `bcrypt` library is used to hash passwords with a randomly generated salt. Check operations use `bcrypt.checkpw()`, ensuring resistance to offline brute-force and dictionary attacks.
- **Session Fixation Prevention**: Upon successful authentication in `/login`, `session.clear()` is called before populating the session with user details. This flushes the existing session and mitigates session fixation attacks.
- **Cryptographic Keys**: Flask's `secret_key` is set to `os.urandom(32)`. This ensures that session cookies are securely signed and cannot be tampered with by the client. *(Note: Because it regenerates on application restart, sessions persist only as long as the application process runs.)*

### Input Validation & Data Handling
- **SQL Injection (SQLi) Prevention**: All interactions with the SQLite database in [database.py] strictly utilize **parameterized queries** (using `?` placeholders) and never concatenate user input directly into SQL strings.
- **Cross-Site Scripting (XSS) Prevention**: User-supplied data, particularly the feedback `message`, is sanitized upon submission using Flask's `markupsafe.escape()`. Furthermore, Flask's Jinja2 templating engine automatically escapes variables by default during rendering.

### Access Control
- **Role-Based Access Control (RBAC)**: The application distinguishes between normal [user] and [admin] roles. Sensitive functions (deleting users, deleting feedback, and promoting users) enforce strict authorization checks verifying `session.get('role') == 'admin'`.
- **Insecure Direct Object Reference (IDOR) Protection**: Actions that modify cross-user state (e.g., changing another user's password via `/change_password/<int:user_id>`) ensure that the requesting `user_id` matches the target `user_id`, *unless* the requester has an [admin] role.
- **Fail-Safe Defaults**: The default role in the databse for a new user is explicitly `'user'`, enforcing the principle of least privilege.

### Cross-Site Request Forgery (CSRF) Mitigation
- **Globally Enabled CSRF Protection**: The `Flask-WTF` extension's `CSRFProtect(app)` is applied, requiring valid CSRF tokens for all modifying (POST/PUT/DELETE) requests application-wide.

---

## 2. Architectural Vulnerability Assessment

The threat model relies on understanding the attack surface. Key trust boundaries exist between the **Web Client (Browser)**, the **Flask Application Server**, and the **SQLite Database System**.

### Vulnerability Diagram



### Risk Assessment & Unmitigated Findings

While the application secures typical web vulnerabilities (SQLi, XSS, CSRF), the architectural assessment reveals specific infrastructure-level threats:

1. **Lack of Encryption in Transit (MITM Vulnerability):** 
   - **Risk**: High
   - **Details**: The Flask application relies heavily on secure cookies and `bcrypt`, but without **HTTPS/TLS** enforcement, session cookies and plaintext passwords (during login/registration) can be intercepted over the network via Man-in-the-Middle attacks.
   - **Recommendation**: Deploy the application behind a reverse proxy (e.g., Nginx, Traefik) that handles TLS termination and enforces `Secure` flags on session cookies.

2. **Data-at-Rest Encryption / File System Security:**
   - **Risk**: Medium
   - **Details**: SQLite stores all data in a single file [app.db]. If an attacker gains read access to the server's file system (via Directory Traversal or Server compromise), the entire database is exposed. While passwords are hashed, personally identifiable information or sensitive feedback could be leaked.
   - **Recommendation**: Ensure strict OS-level file permissions where [app.db] is hosted, ensuring only the application runner process has access.

3. **Volatile Session Management (Denial of Service):**
   - **Risk**: Low
   - **Details**: Utilizing `os.urandom(32)` for the Flask secret key generates a new key each time the app restarts. While secure from a cryptography standpoint, it logs out all active users whenever the server goes down or restarts. Furthermore, standard Flask sessions are un-revocable client-side cookies. 
   - **Recommendation**: Use a deterministic, environment-injected secret key (e.g., from an `.env` file) and consider server-side session stores (like Redis) if session revocation is needed.
