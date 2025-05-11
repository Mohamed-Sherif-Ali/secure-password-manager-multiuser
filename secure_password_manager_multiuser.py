
import os, stat, sys, base64, secrets, string
import sqlite3
from functools import partial
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QAction,
    QFormLayout, QLineEdit, QPushButton, QLabel, QSpinBox,
    QCheckBox, QProgressBar, QToolBar, QMessageBox, QStatusBar,
    QInputDialog
)
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import pyperclip

DB_PATH = "passwords.db"
KDF_ITERS = 600_000

def init_db(path=DB_PATH):
    new = not os.path.exists(path)
    conn = sqlite3.connect(path)
    if new:
        open(path, "a").close()
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            verify_blob TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            service TEXT,
            username TEXT,
            encrypted_password TEXT,
            owner TEXT,
            PRIMARY KEY (service, username, owner),
            FOREIGN KEY (owner) REFERENCES users(username)
        )
    """)
    conn.commit()
    return conn

class EncryptionManager:
    def __init__(self, key: bytes):
        self.key = key

    def _derive(self, salt: bytes) -> bytes:
        return PBKDF2(self.key, salt, dkLen=32, count=KDF_ITERS)

    def encrypt(self, plaintext: str) -> str:
        salt = secrets.token_bytes(16)
        iv   = secrets.token_bytes(16)
        k    = self._derive(salt)
        cipher = AES.new(k, AES.MODE_GCM, iv)
        ct, tag = cipher.encrypt_and_digest(plaintext.encode())
        blob = salt + iv + ct + tag
        return base64.b64encode(blob).decode()

    def decrypt(self, blob_b64: str) -> str:
        blob = base64.b64decode(blob_b64)
        salt, iv = blob[:16], blob[16:32]
        ct, tag  = blob[32:-16], blob[-16:]
        k = self._derive(salt)
        cipher = AES.new(k, AES.MODE_GCM, iv)
        return cipher.decrypt_and_verify(ct, tag).decode()

class UserSession:
    def __init__(self, username: str, crypto: EncryptionManager):
        self.username = username
        self.crypto = crypto

class PasswordDatabase:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.cur = conn.cursor()

    def verify_or_create_user(self, username: str, crypto: EncryptionManager):
        self.cur.execute("SELECT verify_blob FROM users WHERE username=?", (username,))
        row = self.cur.fetchone()
        if row:
            try:
                decrypted = crypto.decrypt(row[0])
                return decrypted == "verifyme"
            except Exception:
                return False
        else:
            verify_blob = crypto.encrypt("verifyme")
            self.cur.execute("INSERT INTO users VALUES (?, ?)", (username, verify_blob))
            self.conn.commit()
            return True

    def add(self, owner, service, username, password, crypto: EncryptionManager):
        enc = crypto.encrypt(password)
        self.cur.execute(
            "INSERT OR REPLACE INTO passwords VALUES (?, ?, ?, ?)",
            (service, username, enc, owner)
        )
        self.conn.commit()

    def get(self, owner, service, username, crypto: EncryptionManager):
        self.cur.execute(
            "SELECT encrypted_password FROM passwords WHERE service=? AND username=? AND owner=?",
            (service, username, owner)
        )
        row = self.cur.fetchone()
        if not row:
            return None
        blob = row[0]
        try:
            return crypto.decrypt(blob)
        except Exception:
            return None

def strength_score(pw: str):
    cats = [
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in string.punctuation for c in pw)
    ]
    return sum(cats), len(pw)

def generate_password(length=16, symbols=True):
    chars = string.ascii_letters + string.digits
    if symbols: chars += string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

class MainWindow(QMainWindow):
    def __init__(self, db: PasswordDatabase, session: UserSession):
        super().__init__()
        self.db = db
        self.session = session
        self.setWindowTitle(f"🔐 Password Manager — {session.username}")
        self.resize(500, 300)
        self._build_ui()
        self._apply_dark_theme()

    def _build_ui(self):
        mb = self.menuBar()
        file_m = mb.addMenu("File")
        exit_a = QAction("Exit", self, shortcut="Ctrl+Q", triggered=self.close)
        file_m.addAction(exit_a)
        help_m = mb.addMenu("Help")
        about_a = QAction("About", self, triggered=self._about)
        help_m.addAction(about_a)

        tb = QToolBar()
        tb.addAction("➕ Add", lambda: self.tabs.setCurrentIndex(0))
        tb.addAction("🔍 Retrieve", lambda: self.tabs.setCurrentIndex(1))
        tb.addAction("🔑 Generate", lambda: self.tabs.setCurrentIndex(2))
        self.addToolBar(tb)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._add_tab(), "Add Entry")
        self.tabs.addTab(self._get_tab(), "Retrieve Entry")
        self.tabs.addTab(self._gen_tab(), "Generate Password")
        self.setCentralWidget(self.tabs)
        self.setStatusBar(QStatusBar())

    def _add_tab(self):
        w = QWidget(); form = QFormLayout(w)
        self.svc_in = QLineEdit(); self.usr_in = QLineEdit(); self.pw_in = QLineEdit()
        self.pw_in.setEchoMode(QLineEdit.Password)
        self.str_bar = QProgressBar(); self.str_bar.setRange(0, 100)
        self.pw_in.textChanged.connect(self._update_strength)
        show_cb = QCheckBox("Show Password")
        show_cb.toggled.connect(lambda: self.pw_in.setEchoMode(QLineEdit.Normal if show_cb.isChecked() else QLineEdit.Password))
        save_btn = QPushButton("Save Entry"); save_btn.clicked.connect(self._save_entry)

        form.addRow("Service:", self.svc_in); form.addRow("Username:", self.usr_in)
        form.addRow("Password:", self.pw_in); form.addRow("Strength:", self.str_bar)
        form.addRow("", show_cb); form.addRow("", save_btn)
        return w

    def _get_tab(self):
        w = QWidget(); form = QFormLayout(w)
        self.svc_get = QLineEdit(); self.usr_get = QLineEdit()
        get_btn = QPushButton("Retrieve"); get_btn.clicked.connect(self._get_entry)
        self.pw_out = QLineEdit(); self.pw_out.setReadOnly(True)
        show_out_cb = QCheckBox("Show"); show_out_cb.toggled.connect(lambda: self.pw_out.setEchoMode(QLineEdit.Normal if show_out_cb.isChecked() else QLineEdit.Password))
        copy_btn = QPushButton("Copy"); copy_btn.clicked.connect(self._copy_pw)
        form.addRow("Service:", self.svc_get); form.addRow("Username:", self.usr_get)
        form.addRow("", get_btn); form.addRow("Password:", self.pw_out)
        form.addRow("", show_out_cb); form.addRow("", copy_btn)
        return w

    def _gen_tab(self):
        w = QWidget(); form = QFormLayout(w)
        self.len_spin = QSpinBox(); self.len_spin.setRange(8, 64); self.len_spin.setValue(16)
        self.sym_cb = QCheckBox("Include symbols"); self.sym_cb.setChecked(True)
        gen_btn = QPushButton("Generate"); gen_btn.clicked.connect(self._generate_pw)
        self.pw_gen = QLineEdit(); self.pw_gen.setReadOnly(True)
        copy_btn = QPushButton("Copy to Clipboard"); copy_btn.clicked.connect(lambda: pyperclip.copy(self.pw_gen.text()))
        form.addRow("Length:", self.len_spin); form.addRow("", self.sym_cb)
        form.addRow("", gen_btn); form.addRow("Password:", self.pw_gen); form.addRow("", copy_btn)
        return w

    def _update_strength(self, text):
        sc, length = strength_score(text)
        val = int((sc / 4) * 100); val = min(val, 25) if length < 8 else val
        self.str_bar.setValue(val)

    def _save_entry(self):
        svc = self.svc_in.text().strip(); usr = self.usr_in.text().strip(); pw = self.pw_in.text()
        if not svc or not usr or not pw:
            self.statusBar().showMessage("All fields required.", 5000); return
        self.db.add(self.session.username, svc, usr, pw, self.session.crypto)
        self.statusBar().showMessage(f"Saved '{svc}:{usr}'", 5000)
        self.svc_in.clear(); self.usr_in.clear(); self.pw_in.clear(); self.str_bar.reset()

    def _get_entry(self):
        svc = self.svc_get.text().strip(); usr = self.usr_get.text().strip()
        if not svc or not usr:
            self.statusBar().showMessage("Both fields required.", 5000); return
        pw = self.db.get(self.session.username, svc, usr, self.session.crypto)
        if pw is None:
            self.statusBar().showMessage("Not found or invalid key.", 5000); return
        self._current_pw = pw; self.pw_out.setText(pw)

    def _copy_pw(self):
        if hasattr(self, "_current_pw"):
            pyperclip.copy(self._current_pw)
            self.statusBar().showMessage("Copied", 3000)
            QTimer.singleShot(30000, lambda: self.pw_out.clear())

    def _generate_pw(self):
        pw = generate_password(self.len_spin.value(), self.sym_cb.isChecked())
        self.pw_gen.setText(pw); self.statusBar().showMessage("Generated", 2000)

    def _about(self):
        QMessageBox.information(self, "About", "Secure Multi-User Password Manager\nAES‑GCM + PBKDF2\n© 2025")

    def _apply_dark_theme(self):
        self.setStyleSheet("""
        QMainWindow, QWidget { background: #2b2b2b; color: #cccccc; }
        QLineEdit, QSpinBox, QProgressBar {
          background: #3c3f41; color: #ffffff; border: 1px solid #555; }
        QPushButton { background: #555; color: #fff; border: none; padding:4px; }
        QPushButton:hover { background: #707070; }
        QMenuBar, QMenu, QToolBar { background: #313335; color: #ccc; }
        QStatusBar { background: #313335; }
        """)

def main():
    app = QApplication(sys.argv)
    user, ok1 = QInputDialog.getText(None, "Username", "Enter username:")
    if not ok1 or not user: return
    mp, ok2 = QInputDialog.getText(None, "Master Password", "Enter master password:", QLineEdit.Password)
    if not ok2 or not mp: return
    key = mp.encode(); mp = None
    conn = init_db()
    crypto = EncryptionManager(key)
    db = PasswordDatabase(conn)
    if not db.verify_or_create_user(user, crypto):
        QMessageBox.warning(None, "Error", "Invalid master password for existing user.")
        return
    session = UserSession(user, crypto)
    w = MainWindow(db, session); w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
