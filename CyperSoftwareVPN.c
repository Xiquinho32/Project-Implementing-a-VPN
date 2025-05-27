// VPNclient.c
// Includes das bibliotecas
#include <stdio.h>     // Input/Output padrão
#include <stdlib.h>    // Funções gerais
#include <string.h>    // Manipulação de strings
#include <unistd.h>    // Funções de POSIX
#include <arpa/inet.h> // Funções de rede para sockets
#include <pthread.h>   // Funções de threads

// Definições de constantes
#define UDP_PORT 8000             // Porta do servidor
#define SERVER_TCP_IP "127.0.0.1" // IP do servidor
#define SERVER_TCP_PORT 8500      // Porta do servidor TCP
#define MANAGER_PORT 8600         // Porta do servidor de gestão

void cifra_cesar(char *msg, int chave) {
    for (int i = 0; msg[i] != '\0'; i++) {
        char c = msg[i];
        if (c >= 'a' && c <= 'z') {
            msg[i] = 'a' + (c - 'a' + chave + 26) % 26;
        } else if (c >= 'A' && c <= 'Z') {
            msg[i] = 'A' + (c - 'A' + chave + 26) % 26;
        }
    }
}

// Função para lidar com o cliente do servidor de gestão
void *handle_manager(void *arg) {
    int client_fd = *(int*)arg;
    char menu[] = "== Menu de Configuração VPNClient ==\n1. Ver estado\n2. Sair\n";
    write(client_fd, menu, strlen(menu));
    close(client_fd);
    free(arg);
    return NULL;
}

// Função para lidar com o servidor de gestão
void *manager_server() {
    int fd, client;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    // Criação do socket para o servidor de gestão
    fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MANAGER_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(fd, 5);

    while (1) {
        client = accept(fd, (struct sockaddr*)&addr, &len);
        int *new_sock = malloc(sizeof(int));
        *new_sock = client;
        pthread_t t;
        pthread_create(&t, NULL, handle_manager, new_sock);
        pthread_detach(t);
    }
}

int main() {
    pthread_t mthread;
    pthread_create(&mthread, NULL, manager_server, NULL);

    // Criação do socket UDP e TCP
    int udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int tcpSock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in udpAddr, serverAddr;

    // Configuração do socket UDP
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_port = htons(UDP_PORT);
    udpAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(udpSock, (struct sockaddr*)&udpAddr, sizeof(udpAddr));

    // Configuração do socket TCP
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_TCP_PORT);
    inet_aton(SERVER_TCP_IP, &serverAddr.sin_addr);

    // Conexão ao servidor TCP
    connect(tcpSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    // Loop para receber mensagens do socket UDP e em seguida encriptar com a cifra de cesar
    char buffer[512];
    while (1) {
        int len = recvfrom(udpSock, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
        buffer[len] = '\0';
        printf("[VPNclient] Mensagem recebida de ProgUDP1 por UDP: %s\n", buffer);

        // Encontra ':' e encripta só a mensagem (payload)
        char *payload = strrchr(buffer, ':');
        if (payload && *(payload + 1) != '\0') {
            payload++; // Aponta para o início do texto a encriptar
            cifra_cesar(payload, 3);
        }

        send(tcpSock, buffer, strlen(buffer), 0);
        printf("[VPNclient] Mensagem encriptada enviada por TCP ao VPNserver\n");
    }

    close(udpSock);
    close(tcpSock);
    return 0;
}
