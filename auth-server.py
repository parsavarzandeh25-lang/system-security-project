import socket
import jwt
import datetime

SECRET_KEY = "my_super_secret_jwt_really_long_enough_key_12345"
ALGO = "HS256" #HMAC with SHA256 (symmetric cryptograohy algo)

def create_token(username):
    payload = {
        'user': username,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)#it's been set to 30 mins to to minimize window of opportunity in case of stolen jwt
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGO)


auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
auth_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
auth_sock.bind(('localhost', 12346))#assignment of the address to the server
auth_sock.listen(1)
print("🔐 Auth Server on 12346 - waiting for login...")

conn, addr = auth_sock.accept()  
print(f"📨 Login from {addr}")
username = conn.recv(1024).decode().strip()
print(f"🔐 Login attempt: {username}")

token = create_token(username)
conn.send(token.encode())
conn.close()
auth_sock.close()
print(f"✅ JWT issued for {username} - Auth server closed")
