import socket
import hashlib
import jwt
import datetime

#Encryption engine

def xor_cipher(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

# JWT CONFIG
JWT_SECRET = "my_super_secret_jwt_really_long_enough_key_12345"
AUTH_PORT = 12346  # auth_server port

#server detailes
host = 'localhost'
port = 12345
secret_key = "ThisIsMySuperSecretKey"

# 1. LOGIN - Get JWT
def get_jwt_token(username="santo"):
    auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_sock.connect(('localhost', AUTH_PORT))
    auth_sock.send(username.encode())
    token = auth_sock.recv(1024).decode()
    auth_sock.close()
    print(f"✅ JWT Token: {token[:20]}...")
    return token

# Get token first
JWT_TOKEN = get_jwt_token("santo")
FAKE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake_payload_data"

tests = [
    ("santo admin access granted", JWT_TOKEN, "✅ TEST 1: original data"),
    ("santo admin access granted again", JWT_TOKEN, "✅ TEST 2: original data"),
    ("santo admin access granted again and again", JWT_TOKEN, "❌ TEST 3: tampered data"),
    ("santo admin access granted also now", FAKE_TOKEN, "🚫 TEST 4: INVALID JWT")
]

for msg, token, desc in tests:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    print(f"\n--- {desc} ---")
    print(f"📤 Sending: {msg}")
    
    # 1. Integrity Hash
    msg_hash = hashlib.sha256(msg.encode()).hexdigest()

    # 2. Tampering data
    if "tampered data" in desc:
        msg = "hacker admin access granted"

    # 3. Encryption
    combined = msg + "|" + msg_hash
    encrypted = xor_cipher(combined, secret_key)
    
    # 4. Payload: JWT | EncryptedData
    full_payload = f"{token}|{encrypted}"
    client_socket.send(full_payload.encode())
    
    # 5. Response
    response = client_socket.recv(1024).decode()
    print(f'📥 Server replied: {response}')
    client_socket.close()

#terminate the connection
end_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
end_socket.connect((host, port))
end_socket.send(b'')  # Empty bytes = END signal
end_socket.close()
print("🏁 END signal sent - server will shutdown")