// CyperSoftwareVPN.c
// Includes das bibliotecas
#include <stdio.h>     // Input/Output padrão
#include <stdlib.h>    // Funções gerais
#include <string.h>    // Manipulação de strings
#include <unistd.h>    // Funções de POSIX
#include <arpa/inet.h> // Funções de rede para sockets
#include <pthread.h>   // Funções de threads
#include <time.h>      // Para srand e time()
#include <ctype.h>

// Definições de constantes
#define UDP_PORT 8000             // Porta do servidor
#define SERVER_TCP_IP "127.0.0.1" // IP do servidor
#define SERVER_TCP_PORT 8500      // Porta do servidor TCP
#define MANAGER_PORT 8600         // Porta do servidor de gestão
#define SIZE 1024

// Parâmetros públicos Diffie-Hellman
#define DH_P 11
#define DH_G 5

// Para cifra de substituição
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHABET_SIZE 26

// Enigma
const char* ROTOR_I = "EKMFLGDQVZNTOWYHXUSPAIBRCJ";
const char* ROTOR_II = "AJDKSIRUXBLHWTMCQGZNPYFVOE";
const char* ROTOR_III = "BDFHJLCPRTXVZNYEIWGAKMUSQO";
const char* REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

typedef struct {
    const char* wiring;
    int position;
    int notch;
} Rotor;

// Função para cálculo modular rápido (potência modular) -> Diffie-Hellman
unsigned long long mod_pow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) { // se o expoente é ímpar
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2;
    }
    return result;
}

// Cifra de César
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

// Enigma processa uma letra através dos rotores e do refletor
void rotate_rotor(Rotor* rotor) {
    rotor->position = (rotor->position + 1) % 26;
}

char enigma_process(Rotor rotors[], int num_rotors, char c) {
    if (c < 'A' || c > 'Z') return c;
    int index = c - 'A';

    // Forward through rotors
    for (int i = 0; i < num_rotors; i++) {
        index = (rotors[i].wiring[(index + rotors[i].position) % 26] - 'A' - rotors[i].position + 26) % 26;
    }
    // Reflector
    index = (REFLECTOR_B[index] - 'A');

    // Backward through rotors
    for (int i = num_rotors - 1; i >= 0; i--) {
        for (int j = 0; j < 26; j++) {
            if (rotors[i].wiring[j] == 'A' + (index + rotors[i].position) % 26) {
                index = (j - rotors[i].position + 26) % 26;
                break;
            }
        }
    }

    // Rotação dos rotores (simples)
    rotate_rotor(&rotors[0]);
    if (rotors[0].position == rotors[0].notch) {
        rotate_rotor(&rotors[1]);
        if (rotors[1].position == rotors[1].notch) {
            rotate_rotor(&rotors[2]);
        }
    }

    return 'A' + index;
}

void enigma_encrypt(char* msg, Rotor rotors[], int num_rotors) {
    for (int i = 0; msg[i] != '\0'; i++) {
        if (isalpha((unsigned char)msg[i])) {
            char upper = toupper((unsigned char)msg[i]);
            char enc = enigma_process(rotors, num_rotors, upper);
            msg[i] = islower((unsigned char)msg[i]) ? tolower(enc) : enc;
        }
    }
}

// Função para gerar uma chave de substituição aleatória
void gerar_sub_key(char *sub_key) {
    strcpy(sub_key, ALPHABET);

    // Fisher-Yates shuffle
    for (int i = ALPHABET_SIZE - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        // Troca sub_key[i] e sub_key[j]
        char temp = sub_key[i];
        sub_key[i] = sub_key[j];
        sub_key[j] = temp;
    }
    sub_key[ALPHABET_SIZE] = '\0'; // Garante terminação
}

// Função para encriptar com a cifra de substituição
void cifra_substituicao(char *texto, const char *sub_key) {
    for (int i = 0; texto[i] != '\0'; i++) {
        char c = texto[i];
        if (c >= 'A' && c <= 'Z') {
            texto[i] = sub_key[c - 'A'];
        } else if (c >= 'a' && c <= 'z') {
            texto[i] = tolower(sub_key[c - 'a']);
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
    "║  4) Informações              ║\n"
    "║  5) Sair                     ║\n"
    "╚══════════════════════════════╝\n"
    "\nEscolha uma opção: ";

const char *menu_criptografia = 
    "╔══════════════════════════════╗\n"
    "║     MENU DE CRIPTOGRAFIA     ║\n"
    "╠══════════════════════════════╣\n"
    "║ 1) Sem Encriptação           ║\n"
    "║ 2) Cifra de César            ║\n"
    "║ 3) Enigma                    ║\n"
    "║ 4) Substituição              ║\n"
    "║ 5) Voltar ao menu principal  ║\n"
    "╚══════════════════════════════╝\n"
    "\nEscolha uma opção: ";

const char *menu_versao =
    "╔════════════════════════════════════╗\n"
    "║            INFORMAÇÕES             ║\n"
    "╠════════════════════════════════════╣\n"
    "║ Versão: 2.3                        ║\n"
    "╠════════════════════════════════════╣\n"
    "║ IP: 127.0.0.1                      ║\n"
    "║ Porta TCP: 8500                    ║\n"
    "╠════════════════════════════════════╣\n"
    "║ © Copyright by Cyphersoftware 2025 ║\n"
    "╚════════════════════════════════════╝\n";

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

    // Diffie-Hellman
    // Inicializar RNG para chave privada
    srand(time(NULL));
    unsigned long long private_key = (rand() % 20) + 1; // [1,20]

    // Calcular chave pública
    unsigned long long public_key = mod_pow(DH_G, private_key, DH_P);

    // Enviar chave pública ao servidor
    char buffer[SIZE];
    snprintf(buffer, sizeof(buffer), "%llu", public_key);
    send(tcpSock, buffer, strlen(buffer), 0);

    // Receber chave pública do servidor
    int len = read(tcpSock, buffer, sizeof(buffer) - 1);
    buffer[len] = '\0';
    unsigned long long server_public_key = strtoull(buffer, NULL, 10);

    // Calcular chave secreta partilhada
    unsigned long long shared_key = mod_pow(server_public_key, private_key, DH_P);

    // Derivar chave da cifra de César (0-25)
    int cesar_key = shared_key % 26;

    //cifra de substituição
    char sub_key[ALPHABET_SIZE + 1];
    gerar_sub_key(sub_key);
    printf("Chave de substituição aleatória: %s\n", sub_key);

    printf("[CyperSoftwareVPN] Chave secreta DH = %llu, chave César derivada = %d\n", shared_key, cesar_key);

    char mensagem_final[512];
    char mensagem_copia[512];
    int hash_valor;
    while (1) {
        memset(buffer, 0, SIZE);
        recvfrom(udpSock, buffer, SIZE, 0, (struct sockaddr*)&udpAddr, &addr_len);

        if (strncmp(buffer, "MENU:criptografia", 10) == 0) {
            sendto(udpSock, menu_criptografia, strlen(menu_criptografia), 0, (struct sockaddr*)&udpAddr, addr_len);
        } else if (strncmp(buffer, "MENU:admin", 10) == 0) {
            sendto(udpSock, menu_admin, strlen(menu_admin), 0, (struct sockaddr*)&udpAddr, addr_len);
        } else if (strncmp(buffer, "MENU:versao", 10) == 0) {
            sendto(udpSock, menu_versao, strlen(menu_versao), 0, (struct sockaddr*)&udpAddr, addr_len);
        } else {

            FILE *logFile;
            char *sep = strchr(buffer, '|');
            if (sep) {
                int modo = atoi(buffer); // Obtém o modo de encriptação
                char *conteudo = sep + 1; // Resto da mensagem

                char *sep2 = strrchr(buffer, ':');

                if (sep2 != NULL && *(sep2 + 1) != '\0') {
                    char *message = sep2 + 1; // Pega a mensagem após o último ':'
                    while (*message == ' ') message++; // Remove espaços iniciais

                    // Guarda a mensagem numa variável
                    strncpy(mensagem_copia, message, sizeof(mensagem_copia) - 1);
                    mensagem_copia[sizeof(mensagem_copia) - 1] = '\0'; // Garante que a string está terminada
                } 

                int hash_valor = hash(mensagem_copia);

                printf("\n--------------------------------------------------------\n");
                printf("[CyperSoftwareVPN] Mensagem recebida de ProgUDP1 por UDP: %s\n", conteudo);
                printf("[CyperSoftwareVPN] Hash da mensagem desencriptada: %d\n", hash_valor);

                char *payload = strrchr(conteudo, ':');
                if (modo == 1) {
                    // Modo 1: Sem encriptação
                    printf("[CyperSoftwareVPN] Modo 1: Mensagem não encriptada\n");
                } else if (modo == 2) {
                    // Modo 2: Cifra de César
                    printf("[CyperSoftwareVPN] Modo 2: Cifra de César\n");
                    // Encontra ':' e encripta só a mensagem (payload)
                    if (payload && *(payload + 1) != '\0') {
                        payload++; // início do texto a encriptar
                        cifra_cesar(payload, cesar_key);
                    }
                } else if (modo == 3) {
                    printf("[CyperSoftwareVPN] Modo 3: Enigma\n");
                    Rotor rotors[3] = {
                        {ROTOR_I, shared_key % 26, 16},
                        {ROTOR_II, (shared_key/26) % 26, 4},
                        {ROTOR_III, (shared_key/676) % 26, 21}
                    };
                    char *payload = strrchr(conteudo, ':');
                    if (payload && *(payload + 1) != '\0') {
                        payload++;
                        enigma_encrypt(payload, rotors, 3);
                    }
                } else if (modo == 4) {
                    cifra_substituicao(payload, sub_key);
                    printf("[CyperSoftwareVPN] Modo 4: Substituição\n");
                } else {
                    printf("[CyperSoftwareVPN] Modo desconhecido\n");
                }

                logFile = fopen("historico.txt", "a");
                if (logFile) {
                    time_t agora = time(NULL);
                    fprintf(logFile, "%s - Data: %s", conteudo, ctime(&agora));
                    fclose(logFile);
                }

                if (modo == 4) {
                    snprintf(mensagem_final, sizeof(mensagem_final), "%d|%d|%s|%s", modo, hash_valor, conteudo, sub_key);
                } else {
                    snprintf(mensagem_final, sizeof(mensagem_final), "%d|%d|%s", modo, hash_valor, conteudo);
                }
                //printf("[CyperSoftwareVPN] Mensagem encriptada: %s\n", conteudo);
                send(tcpSock, mensagem_final, strlen(mensagem_final), 0);
                printf("[CyperSoftwareVPN] Mensagem encriptada enviada por TCP ao VPNserver\n");
            }
        }
    }

    close(udpSock);
    close(tcpSock);
    return 0;
}
