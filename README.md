Chat Application (MsQuic + OpenSSL, C)
=======================================

A secure chat and echo server using MsQuic (https://github.com/microsoft/msquic) and OpenSSL, built in C.
Supports multiple users, authentication, session UCIDs, and broadcast messaging over QUIC.

---

Prerequisites
-------------

- WSL (Windows Subsystem for Linux) — Ubuntu or Debian recommended.
- gcc, make, cmake
- MsQuic library
- OpenSSL

---

1. Install Dependencies
-----------------------

Open your WSL terminal and run:

    sudo apt update
    sudo apt install -y build-essential pkg-config libssl-dev git cmake powershell

---

2. Build and Install MsQuic
---------------------------

Clone the MsQuic repo and initialize submodules:

    git clone https://github.com/microsoft/msquic.git
    cd msquic
    git submodule update --init

Build MsQuic with OpenSSL using PowerShell (pwsh):

    pwsh ./build.ps1 -Config Release --Tls openssl

The library will be built under:
    artifacts/bin/linux/x64_Release_openssl/

Copy the built library so your app can link to it:

    sudo cp ./artifacts/bin/linux/x64_Release_openssl/libmsquic.so /usr/local/lib/
    sudo ldconfig

*If your CPU is not x64 or the output directory is different, adjust the path accordingly.*

---

3. Build Your Application
-------------------------

From your project directory (where echo.c, protocol.c, and utils.c are located):

     gcc -o echo echo.c protocol.c utils.c -lmsquic -lssl -lcrypto -lpthread -lm

---

4. Generate TLS Certificates
----------------------------

If you don’t already have TLS certificates, you can generate self-signed ones:

    mkdir -p certs
    openssl req -x509 -newkey rsa:4096 -nodes -keyout certs/quic_private_key.pem -out certs/quic_certificate.pem -days 365 -subj "/CN=localhost"

---

5. Run the Server
-----------------

    ./echo -server -cert_file:certs/quic_certificate.pem -key_file:certs/quic_private_key.pem

- Type messages to chat.
- Type '/users' to see the online users.

---

6. Run the Client
-----------------

    ./echo -client -unsecure -target:127.0.0.1

- Enter your username and password when prompted.
- Type messages to chat.
- Type 'quit' to disconnect.

---

7. Built-in Users
-----------------

    Username   Password
    -------------------
    alice      pass123
    bob        pass456
    charlie    pass789

---

8. Troubleshooting
------------------

- libmsquic.so not found?
    - Run `sudo ldconfig`
    - Or: `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`
- OpenSSL missing?
    - Run: `sudo apt install libssl-dev openssl`

---

9. Notes
--------

- Server and clients can be run in separate WSL terminals.
- All messages use QUIC and include authentication/session UCID.
- User/password list is hardcoded for demonstration.

---

10. Additional Documents
-------

- Video Demo - https://1513041.mediaspace.kaltura.com/media/1_5wky6w3u
- For chat modifications overview refer to CS544_Protocol_Implementation_part3_kay54.txt
---

11. References
--------------

- MsQuic on GitHub: https://github.com/microsoft/msquic
- OpenSSL Docs: https://www.openssl.org/docs/
- QUIC RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000

