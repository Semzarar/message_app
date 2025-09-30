import sys
import socket
import threading
import struct
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QHBoxLayout, QInputDialog
)
import base64, hashlib

PORT = 5555

# Static key derived from "waffles"
key_bytes = hashlib.sha256(b"waffles").digest()
FERNET_KEY = base64.urlsafe_b64encode(key_bytes)
fernet = Fernet(FERNET_KEY)


class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt Chat Client")
        self.resize(400, 500)
        self.offset = 0   # правильний стартовий offset

        # Layout
        self.layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        self.load_more_btn = QPushButton("Load More")
        self.load_more_btn.clicked.connect(self.load_more_messages)
        top_layout.addWidget(self.load_more_btn)
        self.layout.addLayout(top_layout)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.layout.addWidget(self.chat_area)

        self.input_field = QLineEdit()
        self.input_field.returnPressed.connect(self.send_message)
        self.layout.addWidget(self.input_field)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_btn)
        self.setLayout(self.layout)

        # Server IP
        host, ok = QInputDialog.getText(self, "Server IP", "Enter the server IP address:")
        if not ok or not host:
            self.chat_area.append("No server IP entered. Closing client.")
            return

        self.HOST = host.strip()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client.connect((self.HOST, PORT))
        except Exception as e:
            self.chat_area.append(f"Failed to connect to server: {e}")
            return

        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    # ----------------- Framing ----------------- #
    def send_frame(self, data: bytes):
        self.client.sendall(struct.pack('!I', len(data)) + data)

    def recv_frame(self):
        raw_len = self.client.recv(4)
        if not raw_len:
            return None
        (msg_len,) = struct.unpack('!I', raw_len)
        buf = b''
        while len(buf) < msg_len:
            chunk = self.client.recv(msg_len - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ----------------- Send/Receive ----------------- #
    def send_message(self):
        message = self.input_field.text()
        if message:
            try:
                token = fernet.encrypt(message.encode('utf-8'))
                self.send_frame(token)
                self.chat_area.append(f"You: {message}")
                self.input_field.clear()
            except Exception as e:
                self.chat_area.append(f"Error sending message: {e}")

    def prepend_message(self, text):
        cursor = self.chat_area.textCursor()
        old_scroll = self.chat_area.verticalScrollBar().value()
        cursor.movePosition(cursor.MoveOperation.Start)
        cursor.insertText(text + '\n')
        self.chat_area.verticalScrollBar().setValue(old_scroll + 20)

    def receive_messages(self):
        while True:
            try:
                token = self.recv_frame()
                if token is None:
                    self.chat_area.append("Disconnected from server (no data)")
                    break
                try:
                    text = fernet.decrypt(token).decode('utf-8')
                except Exception as e:
                    self.chat_area.append(f"[Decryption error: {e}]")
                    continue

                if text.startswith("__OLDMSG__"):
                    self.prepend_message(text[9:])
                else:
                    self.chat_area.append(text)
                    # після першого завантаження 50 повідомлень встановлюємо offset
                    if self.offset == 0:
                        self.offset = 50
            except Exception as e:
                self.chat_area.append(f"Error receiving message: {e}")
                break

    def load_more_messages(self):
        try:
            cmd = f"/loadmore {self.offset}"
            token = fernet.encrypt(cmd.encode('utf-8'))
            self.send_frame(token)
            self.offset += 50  # тепер вантажимо блоками по 50
        except Exception as e:
            self.chat_area.append(f"Error loading more messages: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatClient()
    window.show()
    sys.exit(app.exec())