### Features:
1. Login System:
   - Users can log in using their username and password.
   - Passwords are hashed using SHA-256 and stored with a salt for added security.
   - The system tracks login attempts and locks the application after three failed attempts.

2. Signup System:
   - Users can create new accounts with a username and password.
   - Password strength is evaluated using a progress bar and labeled as "Weak," "Medium," or "Strong."
   - Passwords must meet specific criteria: at least 8 characters, uppercase, lowercase, number, and special character.
   - Passwords are hashed with a randomly generated salt before being stored.

3. UI Design:
   - The application uses a gradient background for aesthetic appeal.
   - Buttons and input fields are styled with hover effects and custom borders.
   - The signup form includes a password strength meter and requirements display.

4. Security Measures:
   - Passwords are securely hashed and salted.
   - Password arrays are cleared after use to prevent memory leaks.
   - Login attempts are logged in a file (`login_audit_log.txt`) with timestamps and statuses.

5. Error Handling:
   - Displays error messages for invalid login attempts, weak passwords, or duplicate usernames.
   - Ensures proper handling of file operations for logging.

### Code Structure:
- `Login_page` Class:
  - Handles the login functionality and UI.
  - Includes methods for hashing passwords, logging attempts, and validating user credentials.

- `SignupForm` Class:
  - Handles the signup functionality and UI.
  - Includes methods for password strength evaluation, user registration, and salt generation.

- Main Method:
  - Initializes the application and sets the system look and feel.

## How to Run:
1. Compile the code using a Java compiler.
2. Run the application to display the login page.
3. Use the "Sign Up" button to create a new account.
4. Log in using the newly created credentials.

### Example Usage:
- Default credentials:
  - Username: `admin`
  - Password: `Admin@123`

### File Logging:
- Login attempts are logged in `login_audit_log.txt` with details like username, timestamp, and status.

### Dependencies:
- Java Swing for GUI.
- Java Security for password hashing and salt generation.
