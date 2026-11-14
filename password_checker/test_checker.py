import checker
from checker import check_password


def test_very_short_password_is_weak():
    result = check_password("abc")
    assert result["rating"] == "Weak"


def test_common_pattern_is_weak():
    result = check_password("Password123")
    assert result["rating"] == "Weak"


def test_common_password_is_weak():
    result = check_password("123456")
    assert result["rating"] == "Weak"


def test_medium_password_is_fair():
    result = check_password("Zebra4291")
    assert result["rating"] == "Fair"


def test_long_passphrase_is_strong():
    result = check_password("purple-giraffe-eats-7-mangoes!")
    assert result["rating"] == "Strong"


def test_feedback_mentions_missing_uppercase():
    result = check_password("abc")
    assert "Add uppercase letters." in result["feedback"]


def test_breached_password_becomes_weak(monkeypatch):
    # Pretend the API says this password appeared in 5 breaches.
    monkeypatch.setattr(checker, "check_breach", lambda pw: 5)
    result = check_password("purple-giraffe-eats-7-mangoes!", use_breach_check=True)
    assert result["rating"] == "Weak"


def test_breach_check_failure_does_not_crash(monkeypatch):
    # Pretend there is no internet.
    monkeypatch.setattr(checker, "check_breach", lambda pw: None)
    result = check_password("purple-giraffe-eats-7-mangoes!", use_breach_check=True)
    assert result["rating"] == "Strong"