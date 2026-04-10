"""Unit tests for the password strength checker."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from checker import check_password, calculate_entropy, check_common_patterns


# ─── Strength Classification Tests ──────────────────────────────────

def test_very_weak_password():
    result = check_password("123")
    assert result["strength"] in ("Very Weak", "Weak")
    assert result["score"] < 40


def test_weak_password():
    result = check_password("hello")
    assert result["score"] < 60


def test_fair_password():
    result = check_password("Hello123")
    assert result["score"] >= 20


def test_strong_password():
    result = check_password("MyP@ssw0rd!23")
    assert result["score"] >= 60


def test_very_strong_password():
    result = check_password("X#9kL!mZ@2pQ&wR7")
    assert result["strength"] == "Very Strong"
    assert result["score"] >= 80


# ─── Common Password Detection ──────────────────────────────────────

def test_common_password_detected():
    result = check_password("password")
    assert result["checks"]["is_common"] is True
    assert result["score"] < 40


def test_common_password_case_insensitive():
    result = check_password("PASSWORD")
    assert result["checks"]["is_common"] is True


def test_uncommon_password():
    result = check_password("xK8#mQ2!zW")
    assert result["checks"]["is_common"] is False


# ─── Character Variety Checks ───────────────────────────────────────

def test_has_uppercase():
    result = check_password("Hello")
    assert result["checks"]["has_uppercase"] is True


def test_missing_uppercase():
    result = check_password("hello123")
    assert result["checks"]["has_uppercase"] is False
    assert any("uppercase" in f.lower() for f in result["feedback"])


def test_has_special_chars():
    result = check_password("test!@#")
    assert result["checks"]["has_special"] is True


def test_missing_special_chars():
    result = check_password("Hello123")
    assert result["checks"]["has_special"] is False


# ─── Entropy Tests ──────────────────────────────────────────────────

def test_entropy_increases_with_length():
    short = calculate_entropy("ab")
    long = calculate_entropy("abcdefghij")
    assert long > short


def test_entropy_increases_with_variety():
    lower_only = calculate_entropy("abcdefgh")
    mixed = calculate_entropy("aBcD1234")
    assert mixed > lower_only


def test_entropy_empty_string():
    assert calculate_entropy("") == 0.0


# ─── Pattern Detection Tests ────────────────────────────────────────

def test_detects_repeated_chars():
    warnings = check_common_patterns("aaabbb")
    assert any("repeated" in w.lower() for w in warnings)


def test_detects_sequential_numbers():
    warnings = check_common_patterns("abc12345xyz")
    assert any("sequential" in w.lower() for w in warnings)


def test_detects_keyboard_pattern():
    warnings = check_common_patterns("myqwertypass")
    assert any("keyboard" in w.lower() for w in warnings)


def test_no_patterns_in_random():
    warnings = check_common_patterns("xK8mQ2zW")
    assert len(warnings) == 0


# ─── Edge Cases ─────────────────────────────────────────────────────

def test_empty_password():
    result = check_password("")
    assert result["score"] == 0
    assert result["strength"] == "Very Weak"


def test_single_character():
    result = check_password("a")
    assert result["score"] <= 20


def test_only_spaces():
    result = check_password("        ")
    assert result["strength"] in ("Very Weak", "Weak")


def test_unicode_password():
    result = check_password("Pässwörd!123")
    assert result["score"] > 0


def test_very_long_password():
    result = check_password("aB3!xY7@" * 10)
    assert result["score"] >= 60


# ─── Return Structure Tests ─────────────────────────────────────────

def test_return_has_required_keys():
    result = check_password("test")
    assert "score" in result
    assert "strength" in result
    assert "entropy" in result
    assert "feedback" in result
    assert "checks" in result


def test_score_within_range():
    for pw in ["a", "Hello", "MyP@ss1!", "X#9kL!mZ@2pQ&wR7!!"]:
        result = check_password(pw)
        assert 0 <= result["score"] <= 100
