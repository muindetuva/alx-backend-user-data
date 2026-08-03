# Personal Data Protection

This project demonstrates how to keep personally identifiable information
(PII) out of application logs, read database credentials from environment
variables, and hash and verify passwords securely with bcrypt.

## Modules

- `filtered_logger.py` redacts five sensitive user fields, configures a safe
  logger, and reads users from a credential-protected MySQL database.
- `encrypt_password.py` creates salted password hashes and verifies passwords
  without ever storing the plain-text value.
