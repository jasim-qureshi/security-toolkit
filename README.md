# Security Toolkit

Python tools for security practice. Currently includes a password strength checker; a log analyzer and a phishing email detector are planned.

## Password Strength Checker

Rates a password as Weak, Fair or Strong using:
- Length and character-type rules
- Penalties for repeated characters and common patterns
- A check against a list of common passwords
- A breach check using the Have I Been Pwned "Pwned Passwords" API

### How the breach check protects your password
The password is hashed with SHA-1 and only the first 5 characters of the hash are sent to the API (k-anonymity). The API returns all matching hash endings and the comparison is done locally, so the full password never leaves your computer. SHA-1 is used only because the API requires it.

### Run it
    pip install requests pytest
    python password_checker/checker.py

### Run the tests
    pytest password_checker

### Optional: common-passwords list
Download a common-passwords list from SecLists (github.com/danielmiessler/SecLists, Passwords/Common-Credentials) and save it as `password_checker/common_passwords.txt`.

### Limitations
- Scoring is rule-based, so predictable passwords like `Summer2024!` can score Strong without the breach check.
- The breach check needs an internet connection.