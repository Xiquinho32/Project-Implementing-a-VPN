// VPNserver.c
// Includes das bibliotecas
#include <stdio.h>      // Input/Output padrão
#include <stdlib.h>     // Funções gerais
#include <string.h>     // Manipulação de strings
#include <unistd.h>     // Funções de POSIX
#include <pthread.h>    // Funções de threads
#include <arpa/inet.h>  // Funções de rede para sockets

// Definições de constantes
#define TCP_PORT 8500          // Porta do servidor TCP
#define UDP_TARGET_PORT 9000   // Porta do servidor UDP
#define MANAGER_PORT 8700      // Porta do servidor de gestão


//Função de cifra de cesar
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
    char menu[] = "== Menu de Configuração VPNServer ==\n1. Ver estado\n2. Sair\n";
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

    // Loop para aceitar conexões de clientes
    while (1) {
        client = accept(fd, (struct sockaddr*)&addr, &len);
        int *new_sock = malloc(sizeof(int));
        *new_sock = client;
        pthread_t t;
        pthread_create(&t, NULL, handle_manager, new_sock);
        pthread_detach(t);
    }
}

// Função para processar a conexão TCP
void process_tcp_connection(int client_fd) {
    char buffer[512];
    struct sockaddr_in udpAddr;
    int udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Configuração do endereço do servidor UDP
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_port = htons(UDP_TARGET_PORT);
    udpAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Loop para ler mensagens do cliente TCP e desencripta de volta com a cifra de cesar 
    while (1) {
        int len = read(client_fd, buffer, sizeof(buffer) - 1);
        if (len <= 0) break;
        buffer[len] = '\0';
        printf("[VPNserver] Mensagem encriptada recebida por TCP com sucesso: %s\n", buffer);

        // Encontra o ':' e desencripta só o a mensagem
        char *payload = strrchr(buffer, ':');
        if (payload && *(payload + 1) != '\0') {
            payload++; // Aponta para o início do texto a desencriptar
            cifra_cesar(payload, -3);
        }

        printf("[VPNserver] Mensagem desencriptada: %s\n", buffer);
        sendto(udpSock, buffer, strlen(buffer), 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr));
        printf("[VPNserver] Mensagem enviada por UDP para ProgUDP2\n");
    }

    close(udpSock);
    close(client_fd);
    exit(0);
}

int main() {
    pthread_t mthread;
    pthread_create(&mthread, NULL, manager_server, NULL);

    // Criação do socket TCP
    int tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr, clientAddr;
    socklen_t len = sizeof(clientAddr);

    // Configuração do endereço do servidor TCP
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(tcpSock, (struct sockaddr*)&addr, sizeof(addr));
    listen(tcpSock, 5);

    // Loop para aceitar conexões de clientes TCP
    while (1) {
        int client_fd = accept(tcpSock, (struct sockaddr*)&clientAddr, &len);
        if (fork() == 0) {
            process_tcp_connection(client_fd);
        }
        close(client_fd);
    }

    return 0;
}
