# 🔐 Password Strength Checker

> A Python tool that analyzes passwords against multiple security criteria — length, character variety, entropy, common password lists, and pattern detection — and returns a strength score with actionable feedback.

---

## 🤔 Why This Exists

Weak passwords remain the #1 cause of account breaches. Most password meters only check length and character types. This tool goes further:

- **Entropy calculation** — measures actual randomness, not just rule-checking
- **Common password detection** — flags passwords from known breach databases
- **Pattern detection** — catches keyboard walks (`qwerty`), sequences (`123`), and repeated characters
- **Actionable feedback** — tells users exactly *what* to fix, not just "weak"

---

## 🚀 Quick Start

### CLI Usage

```bash
git clone https://github.com/YOUR_USERNAME/PasswordStrengthChecker.git
cd PasswordStrengthChecker
python src/cli.py
```

```
🔐 Password Strength Checker
  Type 'quit' to exit.

  Enter password (hidden):

  Strength: ████████████░░░░░░░░ 60/100 — Strong

  Entropy:  45.60 bits

  ✅ Uppercase letters
  ✅ Lowercase letters
  ✅ Numbers
  ❌ Special characters
  ✅ Not a common password
  ✅ Minimum length (8+)

  Suggestions:
    → Add special characters (!@#$%^&*)
```

### As a Python Module

```python
from src.checker import check_password

result = check_password("MyP@ssw0rd!")
print(result["score"])      # 75
print(result["strength"])   # "Strong"
print(result["entropy"])    # 65.73
print(result["feedback"])   # ["Great password! No issues found."]
```

---

## 📁 Project Structure

```
PasswordStrengthChecker/
├── src/
│   ├── checker.py        # Core strength analysis logic
│   └── cli.py            # Command-line interface
├── tests/
│   └── test_checker.py   # 26 unit tests
├── data/
│   └── common_passwords.txt  # Top 100 common passwords
├── web/
│   └── index.html        # Browser-based UI (standalone)
├── .gitignore
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🧪 How Scoring Works

| Criteria                 | Max Points |
|--------------------------|-----------|
| Password length          | 30        |
| Character variety (4 types) | 40     |
| Entropy bonus            | 20        |
| Unique character ratio   | 10        |
| **Total**                | **100**   |

**Penalties applied for:**
- Common password match (−40)
- Repeated characters like `aaa` (−10 each)
- Sequential patterns like `123` or `abc` (−10 each)
- Keyboard patterns like `qwerty` (−10 each)

| Score    | Strength    |
|----------|-------------|
| 80–100   | Very Strong |
| 60–79    | Strong      |
| 40–59    | Fair        |
| 20–39    | Weak        |
| 0–19     | Very Weak   |

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

```
26 passed in 0.10s
```

---

## 🗺️ Roadmap

- [x] Core strength scoring engine
- [x] Entropy calculation
- [x] Common password detection
- [x] Pattern detection (sequences, repeats, keyboard walks)
- [x] CLI with colored output
- [x] 26 unit tests
- [ ] Web UI (standalone HTML)
- [ ] Breach database check via Have I Been Pwned API
- [ ] Password generator (suggest strong alternatives)
- [ ] Multilingual common password lists

---

## 📜 License

MIT — see [LICENSE](LICENSE) for details.
