"""
Password Strength Checker
Analyzes passwords against multiple security criteria and returns
a strength score with actionable feedback.
"""

import math
import re
import os

# Path to the common passwords file
COMMON_PASSWORDS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "common_passwords.txt"
)


def load_common_passwords(filepath: str = COMMON_PASSWORDS_FILE) -> set:
    """Load a set of commonly used passwords from a file."""
    try:
        with open(filepath, "r") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


# Load once at module level
COMMON_PASSWORDS = load_common_passwords()


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of a password.
    Higher entropy = more randomness = harder to crack.

    Formula: entropy = length * log2(pool_size)
    where pool_size is the number of unique character types used.
    """
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def check_common_patterns(password: str) -> list[str]:
    """Check for common weak patterns in the password."""
    warnings = []

    # Repeated characters (e.g., "aaa", "111")
    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contains repeated characters (e.g., 'aaa')")

    # Sequential numbers (e.g., "123", "987")
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            nums = [int(c) for c in password[i:i+3]]
            if nums[1] - nums[0] == 1 and nums[2] - nums[1] == 1:
                warnings.append("Contains sequential numbers (e.g., '123')")
                break
            if nums[0] - nums[1] == 1 and nums[1] - nums[2] == 1:
                warnings.append("Contains reverse sequential numbers (e.g., '321')")
                break

    # Sequential letters (e.g., "abc", "xyz")
    lower = password.lower()
    for i in range(len(lower) - 2):
        if lower[i:i+3].isalpha():
            ords = [ord(c) for c in lower[i:i+3]]
            if ords[1] - ords[0] == 1 and ords[2] - ords[1] == 1:
                warnings.append("Contains sequential letters (e.g., 'abc')")
                break

    # Keyboard patterns
    keyboard_patterns = [
        "qwerty", "qwertz", "asdf", "zxcv", "1234", "!@#$",
        "qazwsx", "password", "admin", "letmein",
    ]
    for pattern in keyboard_patterns:
        if pattern in lower:
            warnings.append(f"Contains keyboard pattern: '{pattern}'")
            break

    return warnings


def check_password(password: str) -> dict:
    """
    Analyze a password and return a detailed strength report.

    Returns:
        dict with keys:
            - score (int): 0–100 strength score
            - strength (str): "Very Weak" | "Weak" | "Fair" | "Strong" | "Very Strong"
            - entropy (float): Shannon entropy bits
            - feedback (list[str]): Suggestions for improvement
            - checks (dict): Individual check results
    """
    feedback = []
    score = 0

    # --- Individual Checks ---
    checks = {
        "length": len(password),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digits": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "is_common": password.lower() in COMMON_PASSWORDS,
    }

    # --- Scoring ---

    # Length scoring (up to 30 points)
    if checks["length"] >= 16:
        score += 30
    elif checks["length"] >= 12:
        score += 25
    elif checks["length"] >= 8:
        score += 15
    elif checks["length"] >= 6:
        score += 5
    else:
        feedback.append("Use at least 8 characters (12+ recommended)")

    if checks["length"] < 8:
        feedback.append("Password is too short — minimum 8 characters")

    # Character variety (up to 40 points)
    variety_count = sum([
        checks["has_uppercase"],
        checks["has_lowercase"],
        checks["has_digits"],
        checks["has_special"],
    ])
    score += variety_count * 10

    if not checks["has_uppercase"]:
        feedback.append("Add uppercase letters (A–Z)")
    if not checks["has_lowercase"]:
        feedback.append("Add lowercase letters (a–z)")
    if not checks["has_digits"]:
        feedback.append("Add numbers (0–9)")
    if not checks["has_special"]:
        feedback.append("Add special characters (!@#$%^&*)")

    # Entropy bonus (up to 20 points)
    entropy = calculate_entropy(password)
    checks["entropy"] = round(entropy, 2)

    if entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10
    elif entropy >= 28:
        score += 5

    # Common password penalty
    if checks["is_common"]:
        score = max(score - 40, 0)
        feedback.insert(0, "⚠️  This is a commonly used password — extremely easy to crack!")

    # Pattern penalties
    pattern_warnings = check_common_patterns(password)
    if pattern_warnings:
        score = max(score - len(pattern_warnings) * 10, 0)
        feedback.extend(pattern_warnings)

    # Unique character bonus (up to 10 points)
    unique_ratio = len(set(password)) / len(password) if password else 0
    if unique_ratio >= 0.8:
        score += 10
    elif unique_ratio >= 0.6:
        score += 5

    # Cap at 100
    score = min(score, 100)

    # --- Strength Label ---
    if score >= 80:
        strength = "Very Strong"
    elif score >= 60:
        strength = "Strong"
    elif score >= 40:
        strength = "Fair"
    elif score >= 20:
        strength = "Weak"
    else:
        strength = "Very Weak"

    if not feedback:
        feedback.append("Great password! No issues found.")

    return {
        "score": score,
        "strength": strength,
        "entropy": checks["entropy"],
        "feedback": feedback,
        "checks": checks,
    }
