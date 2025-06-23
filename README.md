<p align="center">
  <a href="https://cyphersoftware.space" target="_blank">
    <img src="https://cyphersoftware.space/wp-content/uploads/2025/05/logoweb.png" alt="Logo" width="200"/>
  </a>
</p>


# 🛡️ Simple VPN Project – UDP over TCP with Encryption

---

## 📋 Execution Order

To ensure correct communication between components, follow this execution order:

1. **VPNserver**
2. **CypherSoftwareVPN**
3. **ProgUDP2**
4. **ProgUDP1**

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
gcc -o CypherSoftwareVPN CypherSoftwareVPN.c -lssl -lcrypto
./CypherSoftwareVPN
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

## Automate compilation

Create a script 
```bash
sudo nano compilar.sh
```

## Script to compile programs in order
```bash
#!/bin/bash

echo "A Compilar VPNserver.c..."
gcc -o VPNserver VPNserver.c || { echo "Erro ao compilar VPNserver.c"; exit 1; }

echo "A Compilar CypherSoftwareVPN.c..."
gcc -o CypherSoftwareVPN CypherSoftwareVPN.c || { echo "Erro ao compilar CypherSoftwareVPN.c"; exit 1; }

echo "A Compilar ProgUDP2.c..."
gcc -o ProgUDP2 ProgUDP2.c || { echo "Erro ao compilar ProgUDP2.c"; exit 1; }

echo "A Compilar ProgUDP1.c com bibliotecas SSL..."
gcc -o ProgUDP1 ProgUDP1.c -lssl -lcrypto || { echo "Erro ao compilar ProgUDP1.c"; exit 1; }

echo "Compilação concluída com sucesso!"
```
Give execute permission tothe file:
```bash
chmod +x compilar.sh
```
Execute the script:
```bash
./compilar.sh
```
Create the alias:
```bash
nano ~/.bashrc
```
Update the configurations:
```bash
source ~/.bashrc
```
Add the following line to the end of the script:
Note: change the path of the file
```bash
alias compilarvpn='~/meus_scripts/compilar.sh'
```
Then you just need to type the alias:
```bash
compilarvpn
```
## 📌 Notes
CypherSoftwareVPN uses OpenSSL for encryption, ensure OpenSSL development libraries are installed.

Run each program in a separate terminal window or tab in the order listed above.

This setup simulates a basic VPN tunnel using TCP for secure transport and UDP for application-level communication.

The file 'utilizadores.txt' stores the data of all users (both regular users and administrators), and the default account is admin:admin.


---

## 🛠️ Troubleshooting
If you encounter issues related to missing SSL headers or libraries:
```bash
sudo apt update
sudo apt install libssl-dev
```
---
