import streamlit as st
import hashlib
import base64
import json
import os
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import bcrypt

# --- Constants ---
DATA_FILE = 'data.json'
USERS_FILE = 'users.json'
ATTEMPTS_FILE = 'attempts.json'
PASSWORD_SALT = b'streamlit_salt'
MAX_ATTEMPTS = 3
COOLDOWN_TIMES = [10, 30, 60]  # seconds

# --- Utility Functions ---
def load_json(path: str) -> dict:
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path: str, data: dict):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

# --- Security ---
def derive_key(passkey: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=PASSWORD_SALT, iterations=250_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))


def encrypt_data(plaintext: str, passkey: str) -> str:
    key = derive_key(passkey)
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str, passkey: str) -> str | None:
    try:
        key = derive_key(passkey)
        return Fernet(key).decrypt(ciphertext.encode()).decode()
    except Exception:
        return None

# --- Password Hashing ---
def hash_passkey(passkey: str) -> str:
    return bcrypt.hashpw(passkey.encode(), bcrypt.gensalt()).decode()


def check_passkey(passkey: str, hashed: str) -> bool:
    return bcrypt.checkpw(passkey.encode(), hashed.encode())

# --- Failed Attempts Tracking ---
attempts = load_json(ATTEMPTS_FILE)

def track_failed(username: str):
    info = attempts.get(username, {"count": 0, "last_fail": 0})
    info['count'] += 1
    info['last_fail'] = time.time()
    attempts[username] = info
    save_json(ATTEMPTS_FILE, attempts)


def is_locked(username: str) -> bool:
    info = attempts.get(username, {"count": 0, "last_fail": 0})
    if info['count'] >= MAX_ATTEMPTS:
        elapsed = time.time() - info['last_fail']
        lockout = COOLDOWN_TIMES[min(info['count'] - MAX_ATTEMPTS, len(COOLDOWN_TIMES)-1)]
        return elapsed < lockout
    return False


def reset_attempts(username: str):
    attempts[username] = {"count": 0, "last_fail": 0}
    save_json(ATTEMPTS_FILE, attempts)

# --- Load Users & Data ---
users = load_json(USERS_FILE)
stored_data = load_json(DATA_FILE)

# --- Session Initialization ---
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user' not in st.session_state:
    st.session_state.user = None
if 'page' not in st.session_state:
    st.session_state.page = 'login'

# --- Navigation Sidebar ---
if st.session_state.authenticated:
    with st.sidebar:
        st.write(f"**User:** {st.session_state.user}")
        if st.button("Home 👤"): st.session_state.page = 'home'
        if st.button("Store 📝"): st.session_state.page = 'store'
        if st.button("Retrieve 🔍"): st.session_state.page = 'retrieve'
        if st.button("Logout 🚪"):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.session_state.page = 'login'

# --- Page Definitions ---
def login_page():
    st.title("🔒 Secure Data Vault")
    st.write("Welcome! This application allows you to securely store and retrieve your sensitive text using strong encryption and passkey protection.")
    mode = st.radio("Action", ["Login", "Register"])
    user = st.text_input("Username")
    pwd = st.text_input("Password", type='password')

    if st.button("Submit"):
        if is_locked(user):
            st.error("Too many failed attempts. Try again later.")
            return
        if mode == 'Register':
            if user in users:
                st.error("Username already exists.")
            else:
                users[user] = {'hash': hash_passkey(pwd)}
                save_json(USERS_FILE, users)
                st.success("Registration successful. Please log in.")
        else:
            if user in users and check_passkey(pwd, users[user]['hash']):
                st.session_state.authenticated = True
                st.session_state.user = user
                reset_attempts(user)
                st.success(f"Welcome back, {user}!")
                st.session_state.page = 'home'
                st.rerun()
            else:
                track_failed(user)
                rem = MAX_ATTEMPTS - attempts.get(user, {}).get('count', 0)
                st.error(f"Invalid credentials. {rem} attempts left.")


def home_page():
    st.title(f"Welcome, {st.session_state.user} 👋")
    st.write("At your vault's home, you can quickly navigate to store new data or retrieve existing encrypted text. Use the sidebar or quick buttons below.")
    if st.button("📝 Store Data"): st.session_state.page = 'store'
    if st.button("🔍 Retrieve Data"): st.session_state.page = 'retrieve'


def store_page():
    st.title("📝 Store Secure Data")
    st.write("Encrypt and save your confidential notes with a passkey only you know. Your data is kept entirely on your machine.")
    txt = st.text_area("Your text to encrypt")
    key = st.text_input("Passkey", type='password')
    if st.button("Encrypt & Store"):
        if txt and key:
            enc = encrypt_data(txt, key)
            stored_data[st.session_state.user] = {'encrypted': enc}
            save_json(DATA_FILE, stored_data)
            st.success("Data encrypted and stored securely.")
        else:
            st.warning("Please provide both text and a passkey.")


def retrieve_page():
    st.title("🔍 Retrieve Secure Data")
    st.write("Decrypt and view your stored notes by entering the original passkey. Multiple incorrect tries will trigger a cooldown.")
    key = st.text_input("Passkey", type='password')
    if st.button("Decrypt Data"):
        entry = stored_data.get(st.session_state.user)
        if entry:
            dec = decrypt_data(entry['encrypted'], key)
            if dec:
                st.success(f"Your decrypted data: {dec}")
                reset_attempts(st.session_state.user)
            else:
                track_failed(st.session_state.user)
                st.error("Incorrect passkey. Please try again.")
        else:
            st.info("No data found. Use 'Store' to add a new entry.")

# --- Router ---
if st.session_state.page == 'login':
    login_page()
elif st.session_state.page == 'home':
    home_page()
elif st.session_state.page == 'store':
    store_page()
elif st.session_state.page == 'retrieve':
    retrieve_page()
