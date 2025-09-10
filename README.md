# 🔐 AES Secure File Transfer – Python

A secure file transfer system built in Python using **AES-GCM encryption**, ensuring confidentiality and integrity of files during transmission over unsecured networks.  

This project simulates real-world secure communication protocols and demonstrates concepts of:
- AES (Advanced Encryption Standard)
- Authenticated Encryption with GCM mode
- Password-based key derivation (PBKDF2-HMAC-SHA256)
- Encrypted file streaming with chunking
- Secure client-server communication

---

## 📂 Project Structure
```

AES-Secure-File-Transfer-Python/
┣ client.py        # Client: encrypts and sends files
┣ server.py        # Server: receives and decrypts files
┣ requirements.txt # Dependencies
┣ README.md        # Project documentation
┣ .gitignore

````

---

## ⚡ Features
- 🔐 AES-GCM encryption → ensures confidentiality + integrity  
- 🔑 PBKDF2 key derivation → strong password-based keys  
- 📡 Socket-based transfer → works over any TCP/IP network  
- 📊 Progress display during sending & receiving  
- 📁 Automatic file saving on server-side  
- ✅ Cross-platform (Windows / Linux / macOS)  

---

## 🛠️ Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/adarshgogate/AES-Secure-File-Transfer-Python.git
cd AES-Secure-File-Transfer-Python
````

### 2. Create a virtual environment

**Windows (PowerShell)**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### 1. Start the server

Run this on the **receiving machine**:

```bash
python server.py --host 0.0.0.0 --port 9000 --password "S3cretPassword!" --out-dir received_files
```

* `--host` → IP to bind the server (`0.0.0.0` = all interfaces)
* `--port` → Port to listen on (default: 9000)
* `--password` → Pre-shared password (must match client)
* `--out-dir` → Directory where files will be stored

### 2. Send a file with the client

Run this on the **sending machine**:

```bash
python client.py --host SERVER_IP --port 9000 --password "S3cretPassword!" path/to/file.txt
```

* Replace `SERVER_IP` with the server’s IP (e.g., `127.0.0.1` if same machine).
* `--password` must match the server’s password.
* Provide the file path you want to send.

### 3. Example Test

**Server (Terminal 1):**

```bash
python server.py --host 127.0.0.1 --port 9000 --password "TestPassword123" --out-dir received_files
```

**Client (Terminal 2):**

```bash
echo Hello AES Secure File Transfer! > sample.txt
python client.py --host 127.0.0.1 --port 9000 --password "TestPassword123" sample.txt
```

**Result:**
File will appear in `received_files/sample.txt` with content:

```
Hello AES Secure File Transfer!
```

---

## 📦 Requirements

* Python 3.8+
* [cryptography](https://pypi.org/project/cryptography/) library

Install with:

```bash
pip install -r requirements.txt
```

---

## 📜 License

MIT License © 2025 [Adarsh Gogate](https://github.com/adarshgogate)


