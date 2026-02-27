# Fake Data Prevention System (JWT + Cryptography)

A secure communication system designed to prevent unauthorized access and data tampering using a multi-layered security stack.

## 🛡️ Security Features
- **Authentication:** Centralized Auth Server issuing **JWT (JSON Web Tokens)** signed with HS256.
- **Confidentiality:** Data payload obfuscation using a symmetric **XOR Cipher**.
- **Integrity:** Verification of data using **SHA-256 Hashing** to detect "fake" or tampered data.

## 🚀 How to Run
1. **Install dependencies:**
   `pip install pyjwt`

2. **Start the Auth Server (Terminal 1):**
   `python auth_server.py`

3. **Start the Main Server (Terminal 2):**
   `python server_side.py`

4. **Run the Client Tests (Terminal 3):**
   `python client_side.py`

## 🧪 Included Test Cases
The client script automatically runs 4 scenarios:
1. **Legit User:** Valid JWT and valid data.
2. **Authorized:** Repeated valid request.
3. **Tampered Hash:** Valid JWT but modified message content (Detects "Fake Data").
4. **Invalid JWT:** Unauthorized access attempt using a fake token.
