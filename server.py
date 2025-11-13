import asyncio
import struct
import base64
import hashlib
from cryptography.fernet import Fernet
import aiosqlite

HOST = "0.0.0.0"
PORT = 443
clients = set()

# ------------------- CRYPTO ------------------- #
key_bytes = hashlib.sha256(b"waffles").digest()
FERNET_KEY = base64.urlsafe_b64encode(key_bytes)
fernet = Fernet(FERNET_KEY)


# ------------------- DATABASE ------------------- #
async def init_db():
    async with aiosqlite.connect("chat_history.db") as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await db.commit()


async def save_message(message: bytes):
    msg_str = message.decode('utf-8', errors='ignore')

    if len(msg_str) > 2_000_000 or not msg_str.strip():
        return

    try:
        async with aiosqlite.connect("chat_history.db") as db:
            await db.execute("INSERT INTO messages (message) VALUES (?)", (msg_str,))
            await db.commit()
    except Exception as e:
        print(f"[DB ERROR] Could not save message: {e}")


async def get_last_messages(limit=50, offset=0):
    async with aiosqlite.connect("chat_history.db") as db:
        cursor = await db.execute("""
            SELECT message FROM messages
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = await cursor.fetchall()
    return [row[0] for row in reversed(rows)]


# ------------------- ASYNC TCP FRAMING ------------------- #
async def send_frame(writer: asyncio.StreamWriter, data: bytes):
    try:
        writer.write(struct.pack('!I', len(data)) + data)
        await writer.drain()
    except Exception as e:
        print(f"[SEND ERROR] {e}")


async def recv_frame(reader: asyncio.StreamReader):
    try:
        raw_len = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None

    msg_len = struct.unpack('!I', raw_len)[0]
    try:
        data = await reader.readexactly(msg_len)
    except asyncio.IncompleteReadError:
        return None
    return data


# ------------------- BROADCAST ------------------- #
async def broadcast(data: bytes, sender_writer):
    to_remove = []
    for w in clients:
        if w != sender_writer:
            try:
                await send_frame(w, fernet.encrypt(data))
            except Exception as e:
                print(f"[BROADCAST ERROR] {e}")
                to_remove.append(w)

    for w in to_remove:
        clients.discard(w)
        w.close()
        await w.wait_closed()


# ------------------- CLIENT HANDLER ------------------- #
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    print(f"[NEW CONNECTION] {addr}")
    clients.add(writer)

    # Send last 50 messages
    for msg in await get_last_messages(limit=50):
        try:
            await send_frame(writer, fernet.encrypt(msg.encode('utf-8')))
        except Exception as e:
            print(f"[SEND OLD MSG ERROR] {e}")

    try:
        while True:
            token = await recv_frame(reader)
            if not token:
                break

            try:
                decrypted = fernet.decrypt(token)
            except Exception as e:
                print(f"[DECRYPT ERROR] {e}")
                continue

            if decrypted.startswith(b"/loadmore"):
                try:
                    offset = int(decrypted.decode().split()[1])
                except Exception:
                    offset = 0
                for m in await get_last_messages(limit=50, offset=offset):
                    t = fernet.encrypt(f"__OLDMSG__{m}".encode('utf-8'))
                    await send_frame(writer, t)
                continue

            await save_message(decrypted)
            await broadcast(decrypted, writer)

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")

    finally:
        print(f"[DISCONNECTED] {addr}")
        clients.discard(writer)
        writer.close()
        await writer.wait_closed()


# ------------------- SERVER START ------------------- #
async def start_server():
    await init_db()
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    print(f"[SERVER STARTED] Listening on {addr}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_server())
