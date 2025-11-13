import sys
import socket
import threading
import struct
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextBrowser,
    QLineEdit, QPushButton, QHBoxLayout, QInputDialog,
    QFileDialog
)
from PyQt6.QtCore import pyqtSignal, QUrl
import base64, hashlib, mimetypes, os
import io
from PIL import Image

PORT = 443

# Static key derived from "waffles"
key_bytes = hashlib.sha256(b"waffles").digest()
FERNET_KEY = base64.urlsafe_b64encode(key_bytes)
fernet = Fernet(FERNET_KEY)


class ChatClient(QWidget):
    message_received = pyqtSignal(str, bool)  # text, prepend flag

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt Chat Client")
        self.resize(400, 650)
        self.offset = 0

        # Store received file bytes temporarily
        self.received_files = {}  # {file_id: (filename, bytes)}

        # Buffer & timer for old messages (to collect batches)
        self.old_message_buffer = []
        self._old_msgs_timer = None
        self._old_msgs_lock = threading.Lock()
        self._OLDMSG_PREFIX = b"__OLDMSG__"

        # Connect signal
        self.message_received.connect(self.update_chat_area)

        # Layout
        self.layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        self.load_more_btn = QPushButton("Load More")
        self.load_more_btn.clicked.connect(self.load_more_messages)
        top_layout.addWidget(self.load_more_btn)
        self.layout.addLayout(top_layout)

        self.chat_area = QTextBrowser()
        self.chat_area.setReadOnly(True)
        self.chat_area.setAcceptRichText(True)
        self.chat_area.setOpenExternalLinks(False)
        self.chat_area.setOpenLinks(False)
        self.chat_area.anchorClicked.connect(self.handle_file_click)
        self.layout.addWidget(self.chat_area)

        # Input + buttons
        input_row = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.returnPressed.connect(self.send_message)
        input_row.addWidget(self.input_field)

        self.attach_img_btn = QPushButton("Attach Image")
        self.attach_img_btn.clicked.connect(self.attach_image)
        input_row.addWidget(self.attach_img_btn)

        #self.attach_file_btn = QPushButton("Attach File")
        #self.attach_file_btn.clicked.connect(self.attach_file)
        #input_row.addWidget(self.attach_file_btn)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)
        input_row.addWidget(self.send_btn)

        self.layout.addLayout(input_row)
        self.setLayout(self.layout)

        # Server IP
        host, ok = QInputDialog.getText(self, "Server IP", "Enter the server IP address:")
        if not ok or not host:
            self.message_received.emit("No server IP entered. Closing client.", False)
            return

        self.HOST = host.strip()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client.connect((self.HOST, PORT))
        except Exception as e:
            self.message_received.emit(f"Failed to connect to server: {e}", False)
            return

        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
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
                self.message_received.emit(f"You: {message}", False)
                self.input_field.clear()
            except Exception as e:
                self.message_received.emit(f"Error sending message: {e}", False)

    # ----------------- Image sending ----------------- #
    def attach_image(self):
        fn, _ = QFileDialog.getOpenFileName(
            self,
            "Select image",
            os.path.expanduser("~"),
            "Images (*.png *.jpg *.jpeg *.gif *.bmp);;All Files (*)"
        )

        if not fn:
            return

        try:
            # Open and resize image to a max width of 300px (maintain aspect ratio)
            with Image.open(fn) as img:
                width, height = img.size
                if width > 300:
                    new_height = int((300 / width) * height)
                    img = img.resize((300, new_height), Image.LANCZOS)

                # Choose output format (JPEG for most, PNG for transparency)
                mime, _ = mimetypes.guess_type(fn)
                if mime and mime.lower() in ("image/png", "image/gif"):
                    fmt = "PNG"
                else:
                    fmt = "JPEG"

                # Convert resized image to bytes
                img_buffer = io.BytesIO()
                img.save(img_buffer, format=fmt, optimize=True, quality=85)
                img_bytes = img_buffer.getvalue()

            # Prepare base64 payload
            if not mime:
                mime = f"image/{fmt.lower()}"

            b64data = base64.b64encode(img_bytes).decode("ascii")
            payload = f"__IMG__{mime}:{b64data}".encode("utf-8")

            # Encrypt and send
            token = fernet.encrypt(payload)
            self.send_frame(token)

            # Emit display signal (scaled width 300px)
            self.message_received.emit(
                f'You sent an image:<br><img src="data:{mime};base64,{b64data}" width="300">',
                False
            )

        except Exception as e:
            self.message_received.emit(f"Error sending image: {e}", False)

    # # ----------------- File sending ----------------- #
    # def attach_file(self):
    #     fn, _ = QFileDialog.getOpenFileName(self, "Select file", os.path.expanduser("~"), "All Files (*)")
    #     if not fn:
    #         return
    #     filesize = os.path.getsize(fn)
    #     if filesize > 500 * 1024 * 1024:
    #         self.message_received.emit("Error: File exceeds 500MB limit.", False)
    #         return
    #     try:
    #         with open(fn, "rb") as f:
    #             file_bytes = f.read()
    #         filename = os.path.basename(fn)
    #         # For live send, send raw bytes (server expects raw bytes after filename:)
    #         payload = f"__FILE__{filename}".encode('utf-8') + b':' + file_bytes
    #         token = fernet.encrypt(payload)
    #         self.send_frame(token)
    #
    #         file_id = str(len(self.received_files))
    #         self.received_files[file_id] = (filename, file_bytes)
    #         html = f"You sent a file: <a href='filedata://{file_id}'>{filename}</a> ({filesize/1024/1024:.2f} MB)"
    #         self.message_received.emit(html, False)
    #     except Exception as e:
    #         self.message_received.emit(f"Error sending file: {e}", False)

    # ----------------- Handle file click ----------------- #
    def handle_file_click(self, url: QUrl):
        file_id = url.toString()[len("filedata://"):]
        if file_id not in self.received_files:
            self.message_received.emit(f"[File not found: {file_id}]", False)
            return
        filename, file_bytes = self.received_files.pop(file_id)
        save_path, ok = QFileDialog.getSaveFileName(self, "Save file", filename)
        if ok and save_path:
            with open(save_path, "wb") as f:
                f.write(file_bytes)
            self.message_received.emit(f"File saved: {save_path}", False)

    # ----------------- Old message batching ----------------- #
    def _start_oldmsg_timer(self):
        """Start or restart a short timer to flush old-message buffer after a small pause."""
        with self._old_msgs_lock:
            if self._old_msgs_timer is not None:
                try:
                    self._old_msgs_timer.cancel()
                except Exception:
                    pass
            # small delay to collect several old messages arriving back-to-back
            self._old_msgs_timer = threading.Timer(0.08, self.flush_old_messages)
            self._old_msgs_timer.daemon = True
            self._old_msgs_timer.start()

    def flush_old_messages(self):
        """Flush buffered old messages to the UI (prepended, in correct order)."""
        with self._old_msgs_lock:
            if not self.old_message_buffer:
                return
            # Emit in reversed order so that oldest ends up at the top correctly
            for msg in reversed(self.old_message_buffer):
                self.message_received.emit(msg, True)
            self.old_message_buffer.clear()
            # cancel & clear timer
            if self._old_msgs_timer is not None:
                try:
                    self._old_msgs_timer.cancel()
                except Exception:
                    pass
                self._old_msgs_timer = None

    # ----------------- GUI updates ----------------- #
    def update_chat_area(self, text, prepend=False):
        """Thread-safe chat update with HTML parsing for old and new messages"""
        cursor = self.chat_area.textCursor()
        old_scroll = self.chat_area.verticalScrollBar().value()

        html_to_insert = text

        # Detect combined old-image prefix (some servers may send the combined form)
        if text.startswith("__OLDMSG____IMG__"):
            try:
                rest = text[len("__OLDMSG____IMG__"):]
                mime, b64 = rest.split(":", 1)
                html_to_insert = f'<img src="data:{mime};base64,{b64}" width="300">'
                prepend = True
            except Exception as e:
                html_to_insert = f"[Old image decode error: {e}]"

        # Regular new image
        elif text.startswith("__IMG__"):
            try:
                rest = text[len("__IMG__"):]
                mime, b64 = rest.split(":", 1)
                html_to_insert = f'<img src="data:{mime};base64,{b64}" width="300">'
            except Exception as e:
                html_to_insert = f"[Image decode error: {e}]"

        # Combined old-file (base64 encoded payload expected)
        elif text.startswith("__OLDMSG____FILE__"):
            try:
                rest = text[len("__OLDMSG____FILE__"):]
                filename, b64 = rest.split(":", 1)
                file_id = str(len(self.received_files))
                self.received_files[file_id] = (filename, base64.b64decode(b64))
                html_to_insert = f'<a href="filedata://{file_id}">{filename}</a>'
                prepend = True
            except Exception as e:
                html_to_insert = f"[Old file decode error: {e}]"

        # Old file marker (when old message contains a __FILE__ payload encoded as base64)
        elif text.startswith("__FILE__"):
            try:
                rest = text[len("__FILE__"):]
                filename, b64 = rest.split(":", 1)
                file_id = str(len(self.received_files))
                # assume base64 for old/file textual messages; decode safely
                self.received_files[file_id] = (filename, base64.b64decode(b64))
                html_to_insert = f'<a href="filedata://{file_id}">{filename}</a>'
            except Exception as e:
                html_to_insert = f"[File decode error: {e}]"

        # Insert using cursor when prepending to avoid re-parsing the whole document (prevents gaps)
        if prepend:
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.insertHtml(html_to_insert + "<br>")
            self.chat_area.setTextCursor(cursor)
            # try to keep scroll stable-ish
            self.chat_area.verticalScrollBar().setValue(old_scroll + 20)
        else:
            self.chat_area.append(html_to_insert)

    # ----------------- Receiving ----------------- #
    def receive_messages(self):
        while True:
            try:
                token = self.recv_frame()
                if token is None:
                    self.message_received.emit("Disconnected from server (no data)", False)
                    break

                try:
                    text = fernet.decrypt(token)
                except Exception as e:
                    self.message_received.emit(f"[Decryption error: {e}]", False)
                    continue

                # Handle image (live)
                if text.startswith(b"__IMG__"):
                    try:
                        rest = text[len(b"__IMG__"):]
                        mime, b64 = rest.split(b":", 1)
                        html = f'Peer sent an image:<br><img src="data:{mime.decode()};base64,{b64.decode()}" width="300">'
                        self.message_received.emit(html, False)
                    except Exception as e:
                        self.message_received.emit(f"[Image decode error: {e}]", False)

                # Handle file (live): format __FILE__filename:<raw bytes>
                elif text.startswith(b"__FILE__"):
                    try:
                        rest = text[len(b"__FILE__"):]
                        sep_index = rest.find(b":")
                        if sep_index == -1:
                            raise ValueError("Invalid file payload")
                        filename_bytes = rest[:sep_index]
                        file_bytes = rest[sep_index + 1:]
                        filename = filename_bytes.decode()
                        file_id = str(len(self.received_files))
                        self.received_files[file_id] = (filename, file_bytes)
                        html = f'Peer sent a file: <a href="filedata://{file_id}">{filename}</a>'
                        self.message_received.emit(html, False)
                    except Exception as e:
                        self.message_received.emit(f"[File decode error: {e}]", False)

                # Handle old messages (buffer them; they may contain __IMG__ or __FILE__ text payloads)
                elif text.startswith(self._OLDMSG_PREFIX):
                    # Correctly strip the full __OLDMSG__ prefix
                    rest = text[len(self._OLDMSG_PREFIX):]
                    try:
                        decoded = rest.decode()
                    except Exception:
                        decoded = rest.decode(errors="ignore")
                    # Append to buffer, then (re)start short timer to flush after a tiny pause
                    with self._old_msgs_lock:
                        self.old_message_buffer.append(decoded)
                    self._start_oldmsg_timer()

                else:
                    # Flush buffered old messages (if any) immediately before showing new normal message
                    self.flush_old_messages()

                    # Normal chat messages
                    try:
                        self.message_received.emit(text.decode(), False)
                    except Exception:
                        # if decode fails, show placeholder
                        self.message_received.emit("[Message decode error]", False)
                    if self.offset == 0:
                        self.offset = 50

            except Exception as e:
                # Flush old messages on error too
                try:
                    self.flush_old_messages()
                except Exception:
                    pass
                self.message_received.emit(f"Error receiving message: {e}", False)
                break

    # ----------------- Load more ----------------- #
    def load_more_messages(self):
        try:
            cmd = f"/loadmore {self.offset}"
            token = fernet.encrypt(cmd.encode('utf-8'))
            self.send_frame(token)
            self.offset += 50
        except Exception as e:
            self.message_received.emit(f"Error loading more messages: {e}", False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatClient()
    window.show()
    sys.exit(app.exec())
