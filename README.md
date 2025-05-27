<p align="center">
  <a href="https://cyphersoftware.space" target="_blank">
    <img src="https://cyphersoftware.space/wp-content/uploads/2025/05/logoweb.png" alt="Logo" width="200"/>
  </a>
</p>


# 🛡️ Simple VPN Project – UDP over TCP with Encryption

---

## 📋 Execution Order

To ensure correct communication between components, follow this execution order:

1. **TCPserver**
2. **TCPclient**
3. **ProgUDP2**
4. **CyperSoftwareVPN**

---

## ⚙️ Installation and Compilation

Before compiling, make sure you have the required libraries installed:

```bash
sudo apt install libssl-dev
```

---

## ✅ Compile and Run

ServerVPN:
```bash
gcc -o VPNserver VPNserver.c
./VPNserver
```
CyperSoftwareVPN:  
```bash 
gcc -o CyperSoftwareVPN CyperSoftwareVPN.c
./CyperSoftwareVPN
```
UDP Program 2:
```bash
gcc -o ProgUDP2 ProgUDP2.c
./ProgUDP2
```
UDP Program 1 (with SSL support):
```bash
gcc -o ProgUDP1 ProgUDP1.c -lssl -lcrypto
./ProgUDP1
```
---

## 📌 Notes
CyperSoftwareVPN uses OpenSSL for encryption, ensure OpenSSL development libraries are installed.

Run each program in a separate terminal window or tab in the order listed above.

This setup simulates a basic VPN tunnel using TCP for secure transport and UDP for application-level communication.

---

## 🛠️ Troubleshooting
If you encounter issues related to missing SSL headers or libraries:
```bash
sudo apt update
sudo apt install libssl-dev
```
---
