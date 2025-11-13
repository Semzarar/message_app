🛡️ Message App — Encrypted Private Group Chat

Message App is a lightweight, end-to-end encrypted messaging platform built in Python.
It lets small groups communicate securely over a local network or private server, with automatic encryption, message history persistence, and image sharing — all without any central cloud service.

<img width="745" height="526" alt="image" src="https://github.com/user-attachments/assets/c3b346ce-61c3-4945-9d7f-065bc4bdbb0a" />

🔒 Key Features

End-to-End Encryption — All messages, files, and images are encrypted using Fernet (AES-128)
.

Closed-Group Messaging — Only connected clients can exchange messages. No external dependencies or logins.

Persistent Chat History — Encrypted messages are stored in a local SQLite database.

Image Attachments — Send images (auto-resized for efficiency) directly in the chat.

Load More Messages — Scroll back through previous conversations securely.

Cross-Platform GUI — Simple PyQt6-based desktop client for Linux, macOS, and Windows.

Zero Cloud, Zero Tracking — All communication stays on your server.

🧠 How It Works

The server (server.py) listens for connections on TCP port 443.

Each client (client.py) connects and exchanges encrypted messages using a shared Fernet key (derived from a passphrase — currently "waffles").

Messages are stored in chat_history.db and re-broadcast to all connected peers.

Clients decrypt and display the messages in a GUI with optional embedded images.

⚙️ Installation
1. Clone the repo
git clone https://github.com/Semzarar/message_app.git
cd message_app

2. Install dependencies

Python 3.10+ recommended.

pip install cryptography PyQt6 Pillow aiosqlite

🚀 Usage
Run the server:
python3 server.py


Server starts on 0.0.0.0:443
It automatically creates chat_history.db to store message history.

Run the client:
python3 client.py


When prompted, enter the server IP address.
Start chatting securely with anyone connected to the same server.

🖼️ Screenshots (optional)
Chat UI	Image Sending

	
🧩 File Structure
message_app/

│

├── client.py         # PyQt6-based encrypted chat client

└── server.py         # Asyncio TCP server with SQLite message persistence


🔐 Security Notes

Uses Fernet symmetric encryption with a SHA-256-derived key.

The current shared key is hardcoded ("waffles").
🔧 You should replace this with your own secure passphrase before deployment:

key_bytes = hashlib.sha256(b"your_secret_passphrase").digest()


Recommended: run the server behind a VPN or TLS proxy for stronger network-level privacy.

🧱 Tech Stack

Python 3.10+

PyQt6 — GUI client

asyncio — concurrent server handling

cryptography (Fernet) — message encryption

aiosqlite — async database storage

Pillow — image processing

🛠️ Roadmap / Ideas

 Configurable encryption key or per-user keys

 Support for file attachments (currently commented out)

 Group rooms / channels

 Encrypted offline message delivery

 Desktop notifications
