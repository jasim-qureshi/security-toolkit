# Security Toolkit

Python tools for security practice: a password strength checker and an SSH log analyzer. A phishing email detector is planned.

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

## SSH Log Analyzer

Reads an OpenSSH auth log and reports suspicious login activity.

What it does:
- Counts failed and successful SSH logins, the top source IPs and the most targeted usernames
- Flags source IPs with many failed logins in a short time (MITRE ATT&CK T1110, Brute Force)
- Flags successful logins that follow many failures from the same IP (possible compromise)
- Handles syslog "message repeated N times" lines by counting each repeated event
- Writes brute_force.csv, suspicious_success.csv and a chart (top_failed_ips.png) to an output folder

### Run it
    pip install pandas matplotlib pytest
    python "Log analyzer/analyze.py" --file path/to/OpenSSH_2k.log

Options: --threshold (failures needed to flag, default 5), --window (minutes, default 10), --top, --year, --out

### Run the tests
    pytest

### Sample data
The analyzer was tested on the 2,000-line OpenSSH sample from the Loghub collection: https://github.com/logpai/loghub (OpenSSH folder). The dataset is not included in this repository. Loghub is a research dataset collection by the LogPAI group; please refer to their repository and cite their paper if you use it.

On that sample the analyzer found 527 failed logins, 1 successful login and 11 source IPs crossing the brute-force threshold. The account "root" was targeted most often.

### Limitations
- Syslog lines contain no year, so the year is assumed (default 2024). It is only used for time calculations.
- The thresholds (5 failures in 10 minutes) are starting points that a real SOC would tune.
- A successful login after failures is only a possible compromise. It can also be a user mistyping a password.
- Only SSH password and publickey events are parsed.
- A source IP shows where traffic came from, not who is behind it.