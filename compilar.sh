#!/bin/bash

echo "A Compilar VPNserver.c..."
gcc -o VPNserver VPNserver.c || { echo "Erro ao compilar VPNserver.c"; exit 1; }

echo "A Compilar CypherSoftwareVPN.c..."
gcc -o CypherSoftwareVPN CypherSoftwareVPN.c -lssl -lcrypto || { echo "Erro ao compilar CypherSoftwareVPN.c"; exit 1; }

echo "A Compilar ProgUDP2.c..."
gcc -o ProgUDP2 ProgUDP2.c || { echo "Erro ao compilar ProgUDP2.c"; exit 1; }

echo "A Compilar ProgUDP1.c com bibliotecas SSL..."
gcc -o ProgUDP1 ProgUDP1.c -lssl -lcrypto || { echo "Erro ao compilar ProgUDP1.c"; exit 1; }

echo "Compilação concluída com sucesso!"