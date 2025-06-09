#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#define UDP_PORT 8000
#define SERVER_TCP_IP "127.0.0.1"
#define SERVER_TCP_PORT 8500 
#define MANAGER_PORT 8600
#define SIZE 1024

void cifra_cesar(char *msg, int chave);

// Função para lidar com o cliente do servidor de gestão
void *handle_manager(void *arg) {
    int client_fd = *(int*)arg;
    char menu[] = "== Menu de Configuração CyperSoftwareVPN ==\n1. Ver estado\n2. Sair\n";
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

const char *menu_admin =
    "╔══════════════════════════════╗\n"
    "║     CypherSoftware VPN       ║\n"
    "╠══════════════════════════════╣\n"
    "║  1) Enviar Mensagem          ║\n"
    "║  2) Registar                 ║\n"
    "║  3) Ver Utilizadores         ║\n"
    "║  4) Versão Software          ║\n"
    "║  5) Sair                     ║\n"
    "╚══════════════════════════════╝\n"
    "\nEscolha uma opcao: ";

const char *menu_criptografia = 
    "╔══════════════════════════════╗\n"
    "║    MENU DE CRIPTOGRAFIA      ║\n"
    "╠══════════════════════════════╣\n"
    "║ 1) Sem Encriptação           ║\n"
    "║ 2) Cifra de César            ║\n"
    "║ 3) Enigma (em breve)         ║\n"
    "║ 4) Substituicao (em breve)   ║\n"
    "║ 5) Voltar ao menu principal  ║\n"
    "╚══════════════════════════════╝\n"
    "\nEscolha uma opcao: ";

const char *menu_versao =
    "╔══════════════════════════════════╗\n"
    "║          Versão Software         ║\n"
    "╠══════════════════════════════════╣\n"
    "║ Versão: 2.2                      ║\n"
    "║ Desenvolvido por: Cyphersoftware ║\n"
    "╚══════════════════════════════════╝\n";

int main() {
    pthread_t mthread;
    pthread_create(&mthread, NULL, manager_server, NULL);

    // Criação do socket UDP e TCP
    int udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int tcpSock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in udpAddr, serverAddr;
    socklen_t addr_len = sizeof(udpAddr);
    //socklen_t clientLen = sizeof(clientAddr);

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

    printf("Servidor CypherSoftwareVPN à escuta no porto %d...\n", UDP_PORT);

    char buffer[SIZE], mensagem[512];
    while (1) {
        memset(buffer, 0, SIZE);
        recvfrom(udpSock, buffer, SIZE, 0, (struct sockaddr*)&udpAddr, &addr_len);

        if (strncmp(buffer, "MENU:criptografia", 10) == 0) {
            //responder_menu_guest(sock, &client_addr, addr_len);
            sendto(udpSock, menu_criptografia, strlen(menu_criptografia), 0, (struct sockaddr*)&udpAddr, addr_len);
        } else if (strncmp(buffer, "MENU:admin", 10) == 0) {
            sendto(udpSock, menu_admin, strlen(menu_admin), 0, (struct sockaddr*)&udpAddr, addr_len);
        } else if (strncmp(buffer, "MENU:versao", 10) == 0) {
            sendto(udpSock, menu_versao, strlen(menu_versao), 0, (struct sockaddr*)&udpAddr, addr_len);
        } else {
            //buffer[len] = '\0';

            FILE *logFile;
            char *sep = strchr(buffer, '|');
            if (sep) {
                int modo = atoi(buffer); // Obtém o modo de encriptação
                char *conteudo = sep + 1; // Resto da mensagem

                printf("\n--------------------------------------------------------\n");
                printf("[CyperSoftwareVPN] Mensagem recebida de ProgUDP1 por UDP: %s\n", conteudo);

                if (modo == 1) {
                    // Modo 1: Sem encriptação
                    printf("[CyperSoftwareVPN] Modo 1: Mensagem não encriptada\n");
                } else if (modo == 2) {
                    // Modo 2: Cifra de César
                    printf("[CyperSoftwareVPN] Modo 2: Cifra de César\n");
                    // Encontra ':' e encripta só a mensagem (payload)
                    char *payload = strrchr(conteudo, ':');
                    if (payload && *(payload + 1) != '\0') {
                        payload++; // Aponta para o início do texto a encriptar
                        cifra_cesar(payload, 3);
                    }
                } else if (modo == 3) {
                    // Modo 3: Enigma (placeholder)
                    printf("[CyperSoftwareVPN] Modo 3: Enigma (não implementado)\n");
                } else if (modo == 4) {
                    // Modo 4: Substituição (placeholder)
                    printf("[CyperSoftwareVPN] Modo 4: Substituição (não implementado)\n");
                } else {
                    printf("[CyperSoftwareVPN] Modo desconhecido\n");
                }

                logFile = fopen("historico.txt", "a");
                if (logFile) {
                    time_t agora = time(NULL);
                    fprintf(logFile, "%s - Data: %s", conteudo, ctime(&agora));
                    fclose(logFile);
                }

                snprintf(mensagem, sizeof(mensagem), "%d|%s", modo, conteudo);
                //printf("[CyperSoftwareVPN] Mensagem encriptada: %s\n", conteudo);
                send(tcpSock, mensagem, strlen(mensagem), 0);
                printf("[CyperSoftwareVPN] Mensagem encriptada enviada por TCP ao VPNserver\n");
            }
        }
    }

    close(udpSock);
    close(tcpSock);
    return 0;
}

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