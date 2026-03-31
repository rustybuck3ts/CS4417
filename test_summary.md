# CS4417 Application Test Suite Report

**Result**: 17 / 17 Tests Passed
**Execution Time**: 27.96s

## Tested Scenarios

### Authentication & Core Flows
| Test Case | Scenario | Status |
| :--- | :--- | :--- |
| [test_register_and_login] | Validates standard user registration and subsequent login. | **PASSED** |
| [test_logout]| Validates that session is destroyed cleanly on logout. | **PASSED** |
| [test_change_password]| Validates that users can change their own password successfully. | **PASSED** |
| [test_index_redirect_not_logged_in]| Ensures unauthorized users are correctly redirected to the `/login` page on the index route. | **PASSED** |

### Input Validation
| Test Case | Scenario | Status |
| :--- | :--- | :--- |
| [test_registration_validation]| Prevents registration with empty credentials or duplicate usernames. | **PASSED** |
| [test_login_validation] | Validates login behavior when presented with empty credentials. | **PASSED** |
| [test_feedback_validation] | Prevents users from submitting empty/blank feedback. | **PASSED** |

### Security Defenses
| Test Case | Scenario | Status |
| :--- | :--- | :--- |
| [test_sql_injection_login] | Attempts a standard SQL injection payload (`admin' OR '1'='1`) into the login portal and verifies it is thwarted. | **PASSED** |
| [test_xss_protection_feedback]| Submits a JavaScript (`<script>`) payload into the feedback form and verifies that the output correctly escapes/sanitizes it on the index page. | **PASSED** |

### Roles and Access Control (Authorization)
| Test Case | Scenario | Status |
| :--- | :--- | :--- |
| [test_admin_promote_and_change_user_password] | Verifies administrators can promote other users to admin and reset user passwords. | **PASSED** |
| [test_unauthorized_admin_access] | Verifies non-admin accounts receive `Unauthorized access` when attempting to access `/admin`. | **PASSED** |
| [test_unauthorized_user_deletion] | Ensures non-admin accounts cannot delete users even via direct request. | **PASSED** |
| [test_unauthorized_feedback_deletion] | Ensures non-admin accounts cannot delete feedback records. | **PASSED** |
| [test_unauthorized_promotion](file:///c:/Users/Rusty/Downloads/cs4417/test_app.py#212-229) | Ensures non-admin accounts cannot promote users via backend request forgery. | **PASSED** |
| [test_admin_delete_self]| Verifies administrators cannot accidentally or maliciously delete their own accounts. | **PASSED** |
| [test_admin_delete_feedback] | Verifies valid administrator accounts can delete system feedback accurately. | **PASSED** |
| [test_unauthorized_password_change] | Ensures users cannot change passwords of user accounts that are not their own. | **PASSED** |
