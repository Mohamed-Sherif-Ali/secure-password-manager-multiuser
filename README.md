# 🔐 Secure Password Manager (Multi-User)

A secure, offline desktop password manager built with **PyQt5**, **SQLite**, and **AES-GCM encryption**, with support for **multiple users**.

---

## 🧠 Features

- Separate login for each user
- AES-GCM encryption with PBKDF2 (600k iterations)
- Encrypted verification check to detect wrong master passwords
- Password generator + strength meter
- Clipboard auto-clear after copy
- Responsive PyQt5 GUI with dark theme

---

## 📂 How It Works

- Each user has their own encryption key (based on master password)
- All saved credentials are user-scoped
- Master passwords are never stored — only a test blob is encrypted for verification

---

## 🚀 Setup

```bash
pip install pyqt5 pyperclip pycryptodome
python secure_password_manager_multiuser.py
