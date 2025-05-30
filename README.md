Secure Chat Application Using Diffie-Hellman Key Exchange and AES Encryption

This project demonstrates a secure chat system implemented in Python using the Diffie-Hellman key exchange protocol and AES encryption for securing message communication between a server and a client.

👨‍💻 Developed By

Himesh B N

Madhuchandan K S

Department of Computer Science and Engineering (IoT and Cybersecurity including Blockchain Technology),
Bangalore Institute of Technology

📖 Project Description

The Secure Chat Application enables two parties (client and server) to exchange messages securely through a symmetric AES key derived from a Diffie-Hellman key exchange. The chat interface is developed using Tkinter for simplicity and ease of use.

🔧 Features

Secure key exchange using Diffie-Hellman

AES encryption with CBC mode

IV-based encryption for every message

Real-time encrypted messaging over sockets

Multi-threaded architecture (no GUI blocking)

Tkinter-based simple GUI interface

⚙️ Requirements

Hardware

Intel i3 or better processor

Minimum 4GB RAM

Software

Python 3.8 or higher

VS Code (recommended)

Python Libraries

pip install cryptography

📝 Installation Guide

1. Clone the Repository

git clone https://github.com/your-repo/SecureChatApplication.git
cd SecureChatApplication

2. (Optional) Create a Virtual Environment

python -m venv venv
# Activate:
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

3. Install Required Packages

pip install cryptography

4. Open in Visual Studio Code

Launch VS Code

Open the project folder

Use integrated terminal to run the files

🚀 How to Run

Step 1: Start the Server

python server.py

Waits for client connection on localhost:9999

Step 2: Start the Client (in a separate terminal)

python client.py

Automatically connects to server and starts secure chat

🔒 Cryptographic Techniques Used

Diffie-Hellman Key Exchange

Used to derive a shared secret key between client and server

Converts shared secret into a 256-bit AES key using SHA-256

AES Encryption (CBC Mode)

Encrypts message using random IVs and PKCS7 padding

Prepends IV to the encrypted message for secure decryption

Sample Code Snippet

# AES Encryption
iv = os.urandom(16)
padder = padding.PKCS7(128).padder()
padded = padder.update(plaintext.encode()) + padder.finalize()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
ciphertext = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

📆 Project Structure

SecureChatApplication/
├── serverGui.py           # Server-side code
├── clientGui.py           # Client-side code
├── README.md           # Project documentation

✅ Advantages

Secure end-to-end encryption

Real-time communication

Easy-to-use interface

Lightweight and portable

❌ Limitations

Weak DH parameters (for demo only)

No authentication or integrity check

Only works over localhost by default

🌟 Future Enhancements

Replace DH with strong key sizes or ECC

Add HMAC for integrity verification

Extend for remote (non-localhost) communication

Implement user authentication and logging



