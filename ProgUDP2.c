// ProgUDp2.c
// Includes das bibliotecas
#include <stdio.h>     // Input/Output padrão
#include <stdlib.h>    // Funções gerais
#include <string.h>    // Manipulação de strings
#include <arpa/inet.h> // Funções de rede para sockets
#include <unistd.h>    // Funções de POSIX

// Definições de constantes
#define PORT 9000    // Porta do servidor UDP

int main() {
    int sock;
    struct sockaddr_in addr, fromAddr;
    char buffer[512];
    socklen_t addrLen = sizeof(fromAddr);

    // Criação do socket UDP
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket UDP");
        exit(1);
    }

    // Configuração do endereço do servidor
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    // Loop para receber mensagens
    while (1) {
        int len = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&fromAddr, &addrLen);
        buffer[len] = '\0';
        printf("\n--------------------------------------------------------\n");
        printf("Recebido do VPNServer: %s\n", buffer);
    }

    close(sock);
    return 0;
}