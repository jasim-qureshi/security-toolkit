import hashlib
import re
from getpass import getpass
from pathlib import Path

import requests

COMMON_PATTERNS = ["password", "qwerty", "12345", "abcde", "letmein", "admin"]
HIBP_URL = "https://api.pwnedpasswords.com/range/"


def load_common_passwords():
    path = Path(__file__).parent / "common_passwords.txt"
    if not path.exists():
        return set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


COMMON_PASSWORDS = load_common_passwords()


def check_breach(password: str):
    """Return how many times the password appears in known breaches.
    Returns None if the check could not be done (e.g. no internet)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(HIBP_URL + prefix, timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        return None
    for line in response.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def check_password(password: str, use_breach_check: bool = False) -> dict:
    score = 0
    feedback = []

    # Length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Use 12 or more characters.")
    else:
        feedback.append("Use at least 8 characters (12+ is better).")

    # Character types
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add digits.")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add symbols like ! @ # $.")

    # Penalties
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeating the same character 3+ times.")
    if any(p in password.lower() for p in COMMON_PATTERNS):
        score -= 2
        feedback.append("Contains a common password pattern.")
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is a very common password. Do not use it.")

    # Breach check (optional, needs internet)
    if use_breach_check:
        count = check_breach(password)
        if count is None:
            feedback.append("Could not reach the breach database (no internet?).")
        elif count > 0:
            score = 0
            feedback.append(
                f"Found in {count:,} known data breaches. Never use it."
            )

    score = max(score, 0)
    if score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Fair"
    else:
        rating = "Strong"

    return {"score": score, "rating": rating, "feedback": feedback}


if __name__ == "__main__":
    pw = input("Enter a password to test: ")
    result = check_password(pw, use_breach_check=True)
    print(f"Rating: {result['rating']} (score {result['score']}/6)")
    for tip in result["feedback"]:
        print(f" - {tip}")