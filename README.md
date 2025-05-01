# Secure Data Vault

A Streamlit-based application that enables users to securely store and retrieve sensitive text snippets locally using strong encryption and passkey protection. The vault uses PBKDF2 key derivation with SHA-256, Fernet symmetric encryption, and bcrypt password hashing. Failed login or decryption attempts trigger progressive cooldowns to mitigate brute-force attacks.

---

## Features

- **User Registration & Authentication**: Register new accounts and log in with bcrypt-hashed passwords.
- **Encrypted Storage**: Encrypt text data client-side with a user-defined passkey (Fernet).
- **Secure Retrieval**: Decrypt and display stored data only after correct passkey entry.
- **Progressive Cooldowns**: Tracks failed attempts and enforces increasing lockout periods.
- **Local Persistence**: All data (users, encrypted entries, attempt logs) are stored as JSON files on disk—no remote dependencies.
- **Sidebar Navigation**: Intuitive Streamlit sidebar for Home, Store, Retrieve, and Logout actions.

---

## Requirements

- Python 3.8+
- Streamlit
- cryptography
- bcrypt

Install via pip:

```bash
pip install streamlit cryptography bcrypt
```

---

## Installation & Running

1. **Clone the repository**
   ```bash
git clone <repository-url>
cd secure-data-vault
```

2. **Install dependencies**
   ```bash
pip install -r requirements.txt
```

3. **Run the app**
   ```bash
streamlit run app.py
```

4. **Access in browser**
   Navigate to `http://localhost:8501`.

---

## Usage

1. **Register** a new username and password.
2. **Log in** using your credentials.
3. Use **Store** to encrypt and save your text with a passkey.
4. Use **Retrieve** to decrypt your text by providing the same passkey.
5. **Logout** when finished.

---

## File Structure

```
secure-data-vault/
├── app.py            # Main Streamlit application
├── data.json         # Encrypted data store
├── users.json        # Registered user credentials
├── attempts.json     # Failed-attempt tracking
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## Security Notes

- **Passkey vs. Password**: The login password (bcrypt-hashed) grants access to the UI, while the passkey (PBKDF2 + Fernet) encrypts the actual text data.
- **Local-Only**: All files reside locally—ensure your machine is secure and backed up.
- **Cooldowns**: After 3 failed attempts, a lockout of 10s → 30s → 60s is enforced.

---

## License

MIT © Syed Zeeshan Iqbal

