import socket, os, hashlib, threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Diffie-Hellman Parameters
P = 23
G = 5

def generate_aes_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    actual_cipher = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(actual_cipher) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")

        self.text_area = scrolledtext.ScrolledText(root, width=60, height=20, state='disabled')
        self.text_area.pack(padx=10, pady=10)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(side='left', padx=(10,0), pady=(0,10))
        self.entry.bind("<Return>", lambda e: self.send_message())

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(side='left', padx=10, pady=(0,10))

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('localhost', 9999))

        threading.Thread(target=self.exchange_keys, daemon=True).start()

    def log(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state='disabled')

    def exchange_keys(self):
        server_public = int(self.client_socket.recv(1024).decode())
        self.private = os.urandom(1)[0] % 10 + 1
        public = pow(G, self.private, P)
        self.client_socket.send(str(public).encode())
        shared_secret = pow(server_public, self.private, P)
        self.aes_key = generate_aes_key(shared_secret)
        self.log("Secure channel established.")
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(2048)
                if not data:
                    break
                msg = decrypt_message(self.aes_key, data)
                if msg == "!exit":
                    self.log("Server ended the session.")
                    break
                self.log(f"Server: {msg}")
            except Exception as e:
                self.log("[Decryption Error]")
                break

    def send_message(self):
        msg = self.entry.get()
        self.entry.delete(0, tk.END)
        if msg:
            self.log(f"You: {msg}")
            enc = encrypt_message(self.aes_key, msg)
            try:
                self.client_socket.send(enc)
                if msg == "!exit":
                    self.client_socket.close()
                    self.root.quit()
            except Exception as e:
                self.log("[Send Error]")

root = tk.Tk()
app = ClientApp(root)
root.mainloop()
