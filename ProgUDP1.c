// ProgUDP1.c
// Includes das bibliotecas
#include <stdio.h>       // Input/Output padrão
#include <stdlib.h>      // Funções gerais (exit, malloc)
#include <unistd.h>      // Funções de POSIX (close, read, write)
#include <string.h>      // Manipulação de strings
#include <arpa/inet.h>   // Funções de rede para sockets (inet_aton, htons)
#include <time.h>        // Manipulação de tempo (login)
#include <openssl/sha.h> // Funções de hash (SHA256)
#include <termios.h>     // Terminal (getch)

// Definições de constantes
#define SERVER_PORT 8000             // Porta do servidor
#define SERVER_IP "127.0.0.1"        // IP do servidor
#define MAX_LEN 50                   // Tamanho máximo para utilizador e password
#define HASH_HEX_LEN 65              // Tamanho do hash SHA256 em hexadecimal
#define FICHEIRO "utilizadores.txt"  // Ficheiro de utilizadores

// Função para ler um caractere sem mostrar no ecrã (usado em passwords)
char getch() {
    struct termios oldt, newt;
    char ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}

// Declarações de funções
void mostrarMenu();
void autenticar(int sock, struct sockaddr_in serverAddr);
void registar();
void verUtilizadores();
void verVersao();
void menuEnviarMensagens();
void limparBuffer();
void lerPassword(char *dest);
void sha256_string(const char *str, char *outputBuffer);
void menuCriptografia(const char *utilizador, int sock, struct sockaddr_in serverAddr);

int main() {
    int sock;
    struct sockaddr_in serverAddr;

    // Criação do socket UDP
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket UDP");
        exit(1);
    }

    // Configuração do endereço do servidor
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &serverAddr.sin_addr);

    // Loop do menu principal
    int escolha;
    do {
        system("clear");
        mostrarMenu();
        printf("\nEscolha uma opção: ");
        scanf("%d", &escolha);
        limparBuffer();

        switch (escolha) {
            case 1:
                autenticar(sock, serverAddr);
                break;
            case 2:
                registar();
                break;
            case 3:
                verUtilizadores();
                break;
            case 4:
                verVersao();
                break;
            case 5:
                printf("\nVolte sempre!\n");
                exit(0);
            default:
                printf("\nOpção inválida. Tente novamente.\n");
                sleep(2);
        }

    } while (escolha != 5);

    close(sock);
    return 0;
}

void mostrarMenu() { // Função para mostrar o menu principal
    printf("╔══════════════════════════════╗\n");
    printf("║     CypherSoftware VPN       ║\n");
    printf("╠══════════════════════════════╣\n");
    printf("║  1) Autenticar               ║\n");
    printf("║  2) Registar                 ║\n");
    printf("║  3) Ver Utilizadores         ║\n");
    printf("║  4) Versão Software          ║\n");
    printf("║  5) Sair                     ║\n");
    printf("╚══════════════════════════════╝\n");
}

// Função para calcular o hash SHA256 de uma string (para password)
void sha256_string(const char *str, char *outputBuffer) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)str, strlen(str), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    outputBuffer[64] = 0;
}

// Função para limpar o buffer do stdin (para evitar problemas com scanf)
void limparBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// Função para ler a password sem mostrar os caracteres no ecrã (através de getch())
void lerPassword(char *dest) {
    char ch;
    int i = 0;
    while ((ch = getch()) != '\n' && ch != '\r') {
        if (i < MAX_LEN - 1) {
            dest[i++] = ch;
            printf("*");
        }
    }
    dest[i] = '\0';
    printf("\n");
}

// Função para registar um novo utilizador
void registar() {
    char utilizador[MAX_LEN], password[MAX_LEN], hash[HASH_HEX_LEN];
    char u[MAX_LEN], p[HASH_HEX_LEN];
    int existente = 0;

    system("clear");
    printf("╔══════════════════════════════╗\n");
    printf("║         Registar             ║\n");
    printf("╚══════════════════════════════╝\n");
    printf("\nUsername:\n> ");
    scanf("%s", utilizador);
    limparBuffer();

    // Verifica se o utilizador já existe (no ficheiro utilizadores.txt)
    FILE *file = fopen(FICHEIRO, "r");
    if (file != NULL) {
        while (fscanf(file, "%s %s", u, p) != EOF) {
            if (strcmp(utilizador, u) == 0) {
                existente = 1;
                break;
            }
        }
        fclose(file);
    }

    if (existente) {
        printf("\n⚠ Utilizador já existe. Escolha outro nome.\n");
        return;
    }

    // Lê a password inserida e calcula o hash SHA256
    printf("\nNova password:\n> ");
    lerPassword(password);
    sha256_string(password, hash);

    // Adiciona o novo utilizador ao ficheiro utilizadores.txt
    file = fopen(FICHEIRO, "a");
    if (file == NULL) {
        printf("\n❌ Erro ao gravar ficheiro.\n");
        return;
    }

    time_t agora = time(NULL);
    fprintf(file, "Utilizador: %s - Password: %s - Data: %s", utilizador, hash, ctime(&agora));
    fclose(file);

    printf("\n✅ Utilizador registado com sucesso!\n");
    printf("\nPressione Enter para continuar...");
    getchar();
}

// Função para autenticar o utilizador
void autenticar(int sock, struct sockaddr_in serverAddr) {
    char utilizador[MAX_LEN], password[MAX_LEN], hashInput[HASH_HEX_LEN];
    char linha[256], u[MAX_LEN], hashArmazenado[HASH_HEX_LEN];
    int tentativas = 0, autenticado = 0;
    FILE *file, *logFile;

    system("clear");
    printf("╔══════════════════════════════╗\n");
    printf("║         Autenticacao         ║\n");
    printf("╚══════════════════════════════╝\n");
    printf("\nUsername:\n> ");
    scanf("%s", utilizador);
    limparBuffer();

    // Verifica se o utilizador existe no ficheiro
    file = fopen(FICHEIRO, "r");
    if (file == NULL) {
        printf("\n❌ Erro ao abrir o ficheiro de utilizadores.\n");
        return;
    }

    int encontrado = 0;
    while (fgets(linha, sizeof(linha), file)) {
        if (sscanf(linha, "Utilizador: %s - Password: %s", u, hashArmazenado) == 2) {
            if (strcmp(utilizador, u) == 0) {
                encontrado = 1;
                break;
            }
        }
    }
    fclose(file);

    // Se o utilizador não foi encontrado
    if (!encontrado) {
        printf("\n⚠ Utilizador '%s' não encontrado.\n", utilizador);
        logFile = fopen("logins.txt", "a");
        if (logFile) {
            time_t agora = time(NULL);
            fprintf(logFile, "%s - login: FALHA (utilizador inexistente) - %s", utilizador, ctime(&agora));
            fclose(logFile);
        }
        return;
    }

    // Tentativas de autenticação
    while (tentativas < 3) {
        printf("\nPassword:\n> ");
        lerPassword(password);
        sha256_string(password, hashInput);

        if (strcmp(hashInput, hashArmazenado) == 0) {
            autenticado = 1;
            break;
        } else {
            tentativas++;
            printf("\n❌ Password incorreta. Tentativa %d/3\n", tentativas);
        }
    }

    // Log do login
    logFile = fopen("logins.txt", "a");
    if (logFile) {
        time_t agora = time(NULL);
        char *timestamp = ctime(&agora);
        timestamp[strcspn(timestamp, "\n")] = 0; // Remove \n
        fprintf(logFile, "%s - login: %s - %s\n", utilizador, autenticado ? "OK" : "FALHA", timestamp);
        fclose(logFile);
    }

    if (autenticado) {
        printf("\n✅ Autenticacao bem-sucedida!\n");
        sleep(2);
        menuCriptografia(utilizador, sock, serverAddr);
    } else {
        printf("\n🚫 Tentativas excedidas.\n");
    }
}

// Função para mostrar o menu com os métodos disponíveis de criptografia
void menuCriptografia(const char *utilizador, int sock, struct sockaddr_in serverAddr) {
    int opcao;
    do {
        system("clear");
        printf("╔══════════════════════════════╗\n");
        printf("║    MENU DE CRIPTOGRAFIA      ║\n");
        printf("╠══════════════════════════════╣\n");
        printf("║ 1) Cifra de César            ║\n");
        printf("║ 2) Enigma (em breve)         ║\n");
        printf("║ 3) Substituicao (em breve)   ║\n");
        printf("║ 4) Voltar ao menu principal  ║\n");
        printf("╚══════════════════════════════╝\n");
        printf("\nEscolha uma opção: ");
        scanf("%d", &opcao);
        limparBuffer();

        switch (opcao) {
            case 1:
                menuEnviarMensagens(utilizador, sock, serverAddr);//("César");
                break;
            case 2:
                menuEnviarMensagens(utilizador, sock, serverAddr);//("Enigma");
                break;
            case 3:
                menuEnviarMensagens(utilizador, sock, serverAddr);//("Substituicao");
                break;
            default:
                printf("\nOpção inválida. Tente novamente.\n");
                sleep(2);
                break;
        }
    } while (opcao != 4);
}

// Função para enviar mensagens através do socket UDP
void menuEnviarMensagens(const char *utilizador, int sock, struct sockaddr_in serverAddr) {
    char buffer[512];
    do {
        system("clear");
        printf("╔══════════════════════════════╗\n");
        printf("║    MENU DE MENSAGENS VPN     ║\n");
        printf("╠══════════════════════════════╣\n");
        printf("║ 1) Enviar mensagem           ║\n");
        printf("║ 2) Sair                      ║\n");
        printf("╚══════════════════════════════╝\n");
        printf("\nEscolha uma opção: ");

        int op;
        scanf("%d", &op);
        limparBuffer();

        if (op == 1) {
            // Ler mensagem do utilizador
            char mensagem[400];
            system("clear");
            printf("Mensagem para enviar: ");
            fgets(mensagem, sizeof(mensagem), stdin);
            mensagem[strcspn(mensagem, "\n")] = 0; // remove newline

            // Obter IP e porto local
            struct sockaddr_in localAddr;
            socklen_t addr_len = sizeof(localAddr);
            getsockname(sock, (struct sockaddr*)&localAddr, &addr_len);

            char ipLocal[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(localAddr.sin_addr), ipLocal, INET_ADDRSTRLEN);
            int portoLocal = ntohs(localAddr.sin_port);

            // Montar mensagem com nome, IP e porto
            snprintf(buffer, sizeof(buffer), "%s (%s:%d) enviou a mensagem: %s", utilizador, ipLocal, portoLocal, mensagem);

            // Enviar para 127.0.0.1:8000 -> CypherSoftware VPN
            sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        } else if (op == 2) {
            break;
        } else {
            printf("\nOpção inválida. Tente novamente.\n");
            sleep(2);
        }
    } while (1);
}

// Função para ver os utilizadores registados
void verUtilizadores() {
    char linha[256];
    char utilizador[MAX_LEN];
    FILE *file = fopen(FICHEIRO, "r");

    system("clear");
    printf("╔══════════════════════════════╗\n");
    printf("║      Utilizadores Registados ║\n");
    printf("╠══════════════════════════════╣\n");

    // Verifica se o ficheiro existe e lê os utilizadores
    if (file == NULL) {
        printf("║ Nenhum utilizador encontrado ║\n");
    } else {
        while (fgets(linha, sizeof(linha), file)) {
            // Procurar o "Utilizador:" na linha e extrair o nome
            if (sscanf(linha, "Utilizador: %s", utilizador) == 1) {
                printf("║ %-28s ║\n", utilizador);
            }
        }
        fclose(file);
    }

    printf("╚══════════════════════════════╝\n");
    printf("\nPressione Enter para continuar...");
    getchar();
}

// Função para mostrar a versão do software
void verVersao() {
    system("clear");
    printf("╔══════════════════════════════════╗\n");
    printf("║          Versão Software         ║\n");
    printf("╠══════════════════════════════════╣\n");
    printf("║ Versão: 1.4                      ║\n");
    printf("║ Desenvolvido por: Cyphersoftware ║\n");
    printf("╚══════════════════════════════════╝\n");
    printf("\nPressione Enter para continuar...");
    getchar();
}
