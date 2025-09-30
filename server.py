import socket
import threading
import sqlite3
from cryptography.fernet import Fernet
import base64, hashlib
import struct

HOST = "0.0.0.0"
PORT = 5555
clients = []

# Static key derived from "waffles"
key_bytes = hashlib.sha256(b"waffles").digest()
FERNET_KEY = base64.urlsafe_b64encode(key_bytes)
fernet = Fernet(FERNET_KEY)


# ------------------- DATABASE ------------------- #
def init_db():
    conn = sqlite3.connect("chat_history.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def save_message(message):
    conn = sqlite3.connect("chat_history.db")
    c = conn.cursor()
    c.execute("INSERT INTO messages (message) VALUES (?)", (message,))
    conn.commit()
    conn.close()


def get_last_messages(limit=50, offset=0):
    conn = sqlite3.connect("chat_history.db")
    c = conn.cursor()
    c.execute("""
        SELECT message FROM messages 
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    msgs = [row[0] for row in reversed(c.fetchall())]
    conn.close()
    return msgs

def get_last_messages_load(limit=50, offset=0):
    conn = sqlite3.connect("chat_history.db")
    c = conn.cursor()
    c.execute("""
        SELECT message FROM messages 
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    msgs = [row[0] for row in c.fetchall()]
    conn.close()
    return msgs


# ------------------- TCP Framing ------------------- #
def send_frame(conn, data: bytes):
    conn.sendall(struct.pack('!I', len(data)) + data)


def recv_frame(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    (msg_len,) = struct.unpack('!I', raw_len)
    buf = b''
    while len(buf) < msg_len:
        chunk = conn.recv(msg_len - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ------------------- SERVER LOGIC ------------------- #
def broadcast(message, conn):
    for client in clients:
        if client != conn:
            try:
                token = fernet.encrypt(message.encode('utf-8'))
                send_frame(client, token)
            except:
                clients.remove(client)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    # Send last 50 messages
    for msg in get_last_messages(limit=50, offset=0):
        try:
            token = fernet.encrypt(msg.encode('utf-8'))
            send_frame(conn, token)
        except:
            pass

    while True:
        try:
            token = recv_frame(conn)
            if not token:
                break
            try:
                decoded_msg = fernet.decrypt(token).decode('utf-8').strip()
            except:
                continue

            # Load more messages
            if decoded_msg.startswith("/loadmore"):
                try:
                    offset = int(decoded_msg.split()[1])
                except:
                    offset = 0
                for m in get_last_messages_load(limit=50, offset=offset):
                    t = fernet.encrypt(f"__OLDMSG__{m}".encode('utf-8'))
                    send_frame(conn, t)
                continue

            save_message(decoded_msg)
            broadcast(decoded_msg, conn)

        except:
            break

    conn.close()
    if conn in clients:
        clients.remove(conn)
    print(f"[DISCONNECTED] {addr} disconnected.")


def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")
    
    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    start_server()


