import socket
import hashlib
import jwt

#Encryption engine
def xor_cipher(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

#secret key of jwt
JWT_SECRET = "my_super_secret_jwt_really_long_enough_key_12345"

"""1 . creating socket
(AF_INET for Ipv4
SOCK_STREAM for TCP)
2 . server setup"""
#1.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
#2.
host = 'localhost'
port = 12345
server_socket.bind((host , port))
secret_key = "ThisIsMySuperSecretKey"

# wait for a request
server_socket.listen(1)
print(f"🔐 Fake Data Prevention Server + JWT listening on" , host , ":" , port,)
print(f">"*15 + "-"*15 + "<"*15,"\n")

while True:
    try:
        print("\n--- 🔄 Waiting for new connection... ---\n")
        client_connection, client_address = server_socket.accept()
        
        # Receive Encrypted data + JWT data 
        raw_data = client_connection.recv(4096).decode('utf-8')
        
        if not raw_data:
            print("🏁 END signal - shutting down!")
            client_connection.close()
            print("-" * 40)
            break

        # 1. Split the packet
        try:
            jwt_token, encrypted_data = raw_data.split('|', 1)
        except ValueError:
            print("❌ Malformed packet structure")
            client_connection.send("❌ ERROR: MALFORMED PACKET".encode())
            client_connection.close()
            continue
        
        # 2. Verify Identity (JWT)
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
            user = payload.get('user', 'unknown')
            print(f"✅ JWT Validated for user: {user}")
        except jwt.ExpiredSignatureError:
            print("❌ Access Denied: Token Expired")
            client_connection.send("❌ FAILED: TOKEN EXPIRED".encode())
            client_connection.close()
            continue
        except jwt.InvalidTokenError:
            print("❌ Access Denied: Invalid Signature")
            client_connection.send("❌ FAILED: UNAUTHORIZED".encode())
            client_connection.close()
            continue

        # 3. Decrypt the Payload
        decrypted_payload = xor_cipher(encrypted_data, secret_key)

        # 4. Verify Integrity (Check for Fake/Tampered Data)
        try:
            received_message, received_hash = decrypted_payload.rsplit('|', 1)
            # Re-calculate hash to compare
            expected_hash = hashlib.sha256(received_message.encode('utf-8')).hexdigest()
            
            if received_hash == expected_hash:
                print(f"🟢 SUCCESS: [{user}] sent valid data: {received_message}")
                client_connection.send(f"✅ ACCEPTED: Data integrity verified".encode())
            else:
                print(f"🚩 ALERT: Data tampered! Hash mismatch for user {user}")
                client_connection.send("❌ FAILED: DATA INTEGRITY BREACH".encode())
        
        except ValueError:
            print("❌ Decryption resulted in unreadable format")
            client_connection.send("❌ FAILED: DECRYPTION ERROR".encode())

        client_connection.close()

    except KeyboardInterrupt:
        print("\n👋 Server shutting down...")
        break
server_socket.close()
print("🏁 Server stopped")
