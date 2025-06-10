// VPNserver.c
// Includes das bibliotecas
#include <stdio.h>      // Input/Output padrão
#include <stdlib.h>     // Funções gerais
#include <string.h>     // Manipulação de strings
#include <unistd.h>     // Funções de POSIX
#include <pthread.h>    // Funções de threads
#include <arpa/inet.h>  // Funções de rede para sockets
#include <time.h>       // Para srand e time()

// Definições de constantes
#define TCP_PORT 8500          // Porta do servidor TCP
#define UDP_TARGET_PORT 9000   // Porta do servidor UDP
#define MANAGER_PORT 8700      // Porta do servidor de gestão

// Parâmetros públicos Diffie-Hellman
#define DH_P 11
#define DH_G 5

// Função para cálculo modular rápido (potência modular)
// +para nao causar overflows
//(base^exp) % mod
unsigned long long mod_pow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2;
    }
    return result;
}

// Função de cifra
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

// Função para calcular o hash de uma mensagem
int hash(const char *message) {
    int sum = 0;
    for (int i = 0; message[i] != '\0'; i++) {
        sum += (unsigned char)message[i];
    }
    return sum;
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

// Função para processar a conexão TCP com Diffie-Hellman
void process_tcp_connection(int client_fd) {
    char buffer[512];
    struct sockaddr_in udpAddr;
    int udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Configuração do endereço do servidor UDP
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_port = htons(UDP_TARGET_PORT);
    udpAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Diffie-Hellman: Inicializar RNG e gerar chave privada
    srand(time(NULL));
    unsigned long long private_key = (rand() % 20) + 1;  // Chave privada do servidor
    unsigned long long public_key = mod_pow(DH_G, private_key, DH_P); // Chave pública do servidor

    // Receber chave pública do cliente
    int len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        close(client_fd);
        close(udpSock);
        return;
    }
    buffer[len] = '\0';
    unsigned long long client_public_key = strtoull(buffer, NULL, 10);

    // Enviar chave pública do servidor para o cliente
    snprintf(buffer, sizeof(buffer), "%llu", public_key);
    send(client_fd, buffer, strlen(buffer), 0);

    // Calcular chave secreta partilhada
    unsigned long long shared_key = mod_pow(client_public_key, private_key, DH_P);
    int cesar_key = shared_key % 26;

    printf("[VPNserver] Chave secreta DH = %llu, chave César derivada = %d\n", shared_key, cesar_key);

    // --- Fim Diffie-Hellman ---

    // Loop para ler mensagens do cliente TCP e desencriptar com a cifra de cesar
    while (1) {
        int len = read(client_fd, buffer, sizeof(buffer) - 1);
        if (len <= 0) break;
        buffer[len] = '\0';

        // Extrair o modo
        char *token = strtok(buffer, "|");
        if (!token) continue;
        int modo = atoi(token);

        // Extrair hash_valor_client
        token = strtok(NULL, "|");
        if (!token) continue;
        int hash_valor_client = atoi(token);

        // Extrair o resto do conteudo
        char *conteudo = strtok(NULL, "");
        if (!conteudo) continue; // 

        char *mensagem = strrchr(conteudo, ':');
        if (mensagem && *(mensagem + 1) != '\0') {
            mensagem++; // Ponto de início da mensagem cifrada
            while (*mensagem == ' ') mensagem++; // Remove espaços iniciais
        } else {
            mensagem = ""; // Se não houver mensagem, define como string vazia
        }

        printf("\n--------------------------------------------------------\n");
        printf("[VPNserver] Mensagem encriptada recebida por TCP com sucesso: %s\n", conteudo);

        if (modo == 1) {
            printf("[VPNserver] Modo 1: Mensagem não encriptada\n");
        } else if (modo == 2) {
            printf("[VPNserver] Modo 2: Cifra de César\n");
            cifra_cesar(mensagem, -cesar_key);
            printf("[VPNserver] Mensagem desencriptada: %s\n", mensagem);
        } else if (modo == 3) {
            // Modo 3: Enigma (placeholder)
            printf("[VPNserver] Modo 3: Enigma (não implementado)\n");
        } else if (modo == 4) {
            // Modo 4: Substituição (placeholder)
            printf("[VPNserver] Modo 4: Substituição (não implementado)\n");
        } else {
            printf("[VPNserver] Modo desconhecido\n");
        }

        // Calcular o hash da mensagem desencriptada
        int hash_valor = hash(mensagem);
        if (hash_valor != hash_valor_client) {
            printf("[VPNserver] Hash da mensagem desencriptada: %d (diferente do recebido: %d)\n", hash_valor, hash_valor_client);
            printf("[VPNserver] Mensagem não enviada por UDP para ProgUDP2 por falta de integridade dos dados!\n");
        } else {
            printf("[VPNserver] Hash da mensagem desencriptada: %d (igual ao recebido: %d)\n", hash_valor, hash_valor_client);
            sendto(udpSock, conteudo, strlen(conteudo), 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr));
            printf("[VPNserver] Mensagem enviada por UDP para ProgUDP2!\n");
        }
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
