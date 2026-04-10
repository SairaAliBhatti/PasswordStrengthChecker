"""
Command-line interface for the Password Strength Checker.
Usage: python cli.py
"""

import getpass
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checker import check_password


# Strength bar colors (ANSI)
COLORS = {
    "Very Weak":   "\033[91m",  # Red
    "Weak":        "\033[91m",  # Red
    "Fair":        "\033[93m",  # Yellow
    "Strong":      "\033[92m",  # Green
    "Very Strong": "\033[96m",  # Cyan
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_bar(score: int, strength: str):
    """Print a visual strength bar."""
    color = COLORS.get(strength, "")
    filled = score // 5  # 20 chars max
    empty = 20 - filled
    bar = f"{color}{'█' * filled}{'░' * empty}{RESET}"
    print(f"\n  Strength: {bar} {BOLD}{color}{score}/100 — {strength}{RESET}")


def print_report(result: dict):
    """Print a formatted password analysis report."""
    print_bar(result["score"], result["strength"])

    print(f"\n  Entropy:  {result['entropy']} bits")

    checks = result["checks"]
    print(f"\n  {'✅' if checks['has_uppercase'] else '❌'} Uppercase letters")
    print(f"  {'✅' if checks['has_lowercase'] else '❌'} Lowercase letters")
    print(f"  {'✅' if checks['has_digits']     else '❌'} Numbers")
    print(f"  {'✅' if checks['has_special']    else '❌'} Special characters")
    print(f"  {'✅' if not checks['is_common']  else '❌'} Not a common password")
    print(f"  {'✅' if checks['length'] >= 8    else '❌'} Minimum length (8+)")

    if result["feedback"]:
        print(f"\n  {BOLD}Suggestions:{RESET}")
        for tip in result["feedback"]:
            print(f"    → {tip}")

    print()


def main():
    print(f"\n{BOLD}🔐 Password Strength Checker{RESET}")
    print("  Type 'quit' to exit.\n")

    while True:
        password = getpass.getpass("  Enter password (hidden): ")

        if password.lower() == "quit":
            print("  Goodbye!\n")
            break

        if not password:
            print("  Please enter a password.\n")
            continue

        result = check_password(password)
        print_report(result)


if __name__ == "__main__":
    main()
