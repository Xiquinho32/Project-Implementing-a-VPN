// Includes das bibliotecas
#include <stdio.h>       // Input/Output padrão
#include <stdlib.h>      // Funções gerais (exit, malloc)
#include <unistd.h>      // Funções de POSIX (close, read, write)
#include <string.h>      // Manipulação de strings
#include <arpa/inet.h>   // Funções de rede para sockets (inet_aton, htons)
#include <time.h>        // Manipulação de tempo (login)
#include <openssl/sha.h> // Funções de hash (SHA256)
#include <termios.h>     // Terminal (getch)

#define SERVER_PORT 8000
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024
#define MAX_LEN 50                   // Tamanho máximo para utilizador e password
#define HASH_HEX_LEN 65              // Tamanho do hash SHA256 em hexadecimal

typedef struct {
    char tipo[20];
    char nome[MAX_LEN];
} UtilizadorInfo;

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

// Função para limpar o buffer do stdin (para evitar problemas com scanf)
void limparBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void menu_inicial(int sock, struct sockaddr_in serverAddr);
void pedirMenu(int sockfd, struct sockaddr_in serverAddr, char request[]);
void autenticar(int sock, struct sockaddr_in serverAddr);
void lerPassword(char *dest);
void sha256_string(const char *str, char *outputBuffer);
void menu_admin(int sock, struct sockaddr_in serverAddr, const char *utilizador);
void menuCriptografia(int sock, struct sockaddr_in serverAddr, const char *utilizador, int tipo);
void menuEnviarMensagens(int sock, struct sockaddr_in serverAddr, const char *utilizador, int modo);
void registar(int sock, struct sockaddr_in serverAddr, const char *utilizador);
void verUtilizadores(int sock, struct sockaddr_in serverAddr, const char *utilizador);
void verVersao(int sock, struct sockaddr_in serverAddr, const char *utilizador);

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


    menu_inicial(sock, serverAddr);
    return 0;
}

void menu_inicial(int sock, struct sockaddr_in serverAddr) {
    char opcao;
    char username[100], user_type[10];

    while (1) {
        system("clear");
        printf("╔══════════════════════════════╗\n");
        printf("║     CypherSoftware VPN       ║\n");
        printf("║            Login             ║\n");
        printf("╠══════════════════════════════╣\n");
        printf("║  1) Autenticar               ║\n");
        printf("║  2) Sair                     ║\n");
        printf("╚══════════════════════════════╝\n");
        printf("Escolha uma opção: ");
        scanf(" %c", &opcao);
        //limparBuffer();

        switch (opcao) {
            case '1':
                autenticar(sock, serverAddr);
                break;
            case '2':
                printf("\nVolte Sempre!\n");
                exit(0);
            default:
                printf("Opção inválida.\n");
        }
        sleep(1); // Pausa para o utilizador ver a mensagem
    }
}

void pedirMenu(int sockfd, struct sockaddr_in serverAddr, char request[]) {
    sendto(sockfd, request, strlen(request), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    char menu_buffer[BUFFER_SIZE];
    socklen_t addrlen = sizeof(serverAddr);
    recvfrom(sockfd, menu_buffer, sizeof(menu_buffer), 0, (struct sockaddr*)&serverAddr, &addrlen);

    printf("\n%s\n", menu_buffer);
}

void autenticar(int sock, struct sockaddr_in serverAddr) {
    char utilizador[MAX_LEN], password[MAX_LEN], hashInput[HASH_HEX_LEN];
    char linha[256], u[MAX_LEN], hashArmazenado[HASH_HEX_LEN], tipo_str[20];
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
    file = fopen("utilizadores.txt", "r");
    if (file == NULL) {
        printf("\n❌ Erro ao abrir o ficheiro de utilizadores.\n");
        return;
    }

    int encontrado = 0;
    while (fgets(linha, sizeof(linha), file)) {
        if (sscanf(linha, "Tipo: %s - Utilizador: %s - Password: %s", tipo_str, u, hashArmazenado) == 3) {
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
        fprintf(logFile, "%s - login: %s - %s\n", utilizador, autenticado ? "OK" : "FALHA (password incorreta)", timestamp);
        fclose(logFile);
    }

    if (autenticado) {
        printf("\n✅ Autenticação bem-sucedida! %s autenticado como %s!\n", utilizador, tipo_str);
        sleep(4);
        // Redireciona para o menu correto com base no tipo de utilizador
        if (strcmp(tipo_str, "Admin") == 0) {
            menu_admin(sock, serverAddr, utilizador);
        } else {
            menuCriptografia(sock, serverAddr, utilizador, 1);
        }
    } else {
        printf("\n🚫 Tentativas excedidas.\n");
        sleep(2);
    }
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

// Função para calcular o hash SHA256 de uma string (para password)
void sha256_string(const char *str, char *outputBuffer) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)str, strlen(str), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    outputBuffer[64] = 0;
}

void menu_admin(int sock, struct sockaddr_in serverAddr, const char *utilizador) {
    char opcao;
    while (1) {
        system("clear");
        pedirMenu(sock, serverAddr, "MENU:admin");
        scanf(" %c", &opcao);
        //limparBuffer();

        switch (opcao) {
            case '1':
                menuCriptografia(sock, serverAddr, utilizador, 2);
                break;
            case '2':
                registar(sock, serverAddr, utilizador);
                break;
            case '3':
                verUtilizadores(sock, serverAddr, utilizador);
                break;
            case '4':
                verVersao(sock, serverAddr, utilizador);
                break;
            case '5':
                menu_inicial(sock, serverAddr);
                break;
            default:
                printf("Opção inválida.\n");
        }
    }
}

void menuCriptografia(int sock, struct sockaddr_in serverAddr, const char *utilizador, int tipo) {
    char opcao;
    int modo = 0;
    do {
        system("clear");
        pedirMenu(sock, serverAddr, "MENU:criptografia");
        scanf(" %c", &opcao);
        //limparBuffer();

        switch (opcao) {
            case '1':
                modo = 1; // Sem encriptação
                menuEnviarMensagens(sock, serverAddr, utilizador, modo);
                break;
            case '2':
                modo = 2; // Cifra de César
                menuEnviarMensagens(sock, serverAddr, utilizador, modo);
                break;
            case '3':
                modo = 3; // Enigma
                menuEnviarMensagens(sock, serverAddr, utilizador, modo);
                break;
            case '4':
                modo = 4; // Substituição
                menuEnviarMensagens(sock, serverAddr, utilizador, modo);
                break;
            case '5':
                if (tipo == 1) {
                    menu_inicial(sock, serverAddr);
                } else {
                    menu_admin(sock, serverAddr, utilizador);
                }
                break;
            default:
                printf("\nOpção inválida. Tente novamente.\n");
                sleep(2);
                break;
        }
    } while (opcao != 5);
}

void menuEnviarMensagens(int sock, struct sockaddr_in serverAddr, const char *utilizador, int modo) {
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
            snprintf(buffer, sizeof(buffer), "%d|%s (%s:%d) enviou a mensagem: %s", modo, utilizador, ipLocal, portoLocal, mensagem);

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

// Função para registar um novo utilizador
void registar(int sock, struct sockaddr_in serverAddr, const char *utilizador) {
    char utilizador_criar[MAX_LEN], u[MAX_LEN], password[MAX_LEN], p[MAX_LEN], confirmar[MAX_LEN], hash[HASH_HEX_LEN];
    char linha[512];
    int existente = 0;
    int tipo = 0;
    char tipo_str[20];

    system("clear");
    printf("╔══════════════════════════════╗\n");
    printf("║           Registar           ║\n");
    printf("╚══════════════════════════════╝\n");
    printf("\nUsername:\n> ");
    scanf("%s", utilizador_criar);
    limparBuffer();

    // Verifica se o utilizador já existe (no ficheiro utilizadores.txt)
    FILE *usersfile = fopen("utilizadores.txt", "r");
    if (usersfile != NULL) {
        while (fgets(linha, sizeof(linha), usersfile) != NULL) {
        // Tenta encontrar a parte "Utilizador: <nome>"
        char *ptr = strstr(linha, "Utilizador: ");
        if (ptr != NULL) {
            ptr += strlen("Utilizador: ");
            char nome_existente[MAX_LEN];
            sscanf(ptr, "%s", nome_existente);
            if (strcmp(utilizador_criar, nome_existente) == 0) {
                existente = 1;
                break;
            }
        }
    }
    fclose(usersfile);
    }

    if (existente) {
        printf("\n⚠ Nome de utilizador já existe. Escolha outro nome.\n");
        return;
    }

    // Lê a password inserida e calcula o hash SHA256
    printf("\nNova password:\n> ");
    lerPassword(password);
    printf("Confirme a password:\n> ");
    lerPassword(confirmar);

    if (strcmp(password, confirmar) != 0) {
        printf("\n❌ As passwords não coincidem. Tente novamente.\n");
        return;
    }

    // Escolher tipo de utilizador
    do {
        printf("\nTipo de utilizador:\n1 - Utilizador\n2 - Admin\n> ");
        scanf("%d", &tipo);
        limparBuffer();
    } while (tipo != 1 && tipo != 2);

    strcpy(tipo_str, (tipo == 1) ? "Utilizador" : "Admin");

    sha256_string(password, hash);

    // Adiciona o novo utilizador ao ficheiro utilizadores.txt
    usersfile = fopen("utilizadores.txt", "a");
    if (usersfile == NULL) {
        printf("\n❌ Erro ao gravar ficheiro.\n");
        return;
    }

    time_t agora = time(NULL);
    fprintf(usersfile, "Tipo: %s - Utilizador: %s - Password: %s - Data: %s", tipo_str, utilizador_criar, hash, ctime(&agora));
    fclose(usersfile);

    printf("\n✅ %s '%s' registado com sucesso!\n", tipo_str, utilizador_criar);
    printf("\nPressione Enter para continuar...");
    getchar();
    limparBuffer();
    menu_admin(sock, serverAddr, utilizador);
}

// Função para comparar dois UtilizadorInfo para ordenar
int compararUtilizadores(const void *a, const void *b) {
    UtilizadorInfo *ua = (UtilizadorInfo *)a;
    UtilizadorInfo *ub = (UtilizadorInfo *)b;

    // Primeiro ordena por tipo: Admin antes de Utilizador
    int tipo_cmp = strcmp(ua->tipo, ub->tipo);
    if (tipo_cmp != 0) {
        if (strcmp(ua->tipo, "Admin") == 0) return -1;
        else return 1;
    }

    // Se o tipo for igual, ordena por nome
    return strcmp(ua->nome, ub->nome);
}

// Função para ver os utilizadores registados
void verUtilizadores(int sock, struct sockaddr_in serverAddr, const char *utilizador) {
    UtilizadorInfo lista[100];
    int total = 0;
    char linha[256];
    FILE *file = fopen("utilizadores.txt", "r");

    system("clear");
    printf("╔══════════════════════════════╗\n");
    printf("║    Utilizadores Registados   ║\n");
    printf("╠══════════════════════════════╣\n");

    // Verifica se o ficheiro existe e lê os utilizadores
    if (file == NULL) {
        printf("║ Nenhum utilizador encontrado ║\n");
    } else {
        while (fgets(linha, sizeof(linha), file) != NULL) {
            char tipo[20], nome[MAX_LEN];

            // Exemplo: Tipo: Admin - Utilizador: Nome - Password: ...
            if (sscanf(linha, "Tipo: %[^-]- Utilizador: %[^-]", tipo, nome) == 2) {
                // Remove espaços no final de tipo e nome
                tipo[strcspn(tipo, " ")] = 0;
                nome[strcspn(nome, " ")] = 0;

                strcpy(lista[total].tipo, tipo);
                strcpy(lista[total].nome, nome);
                total++;
            }
        }
        fclose(file);

        // Ordenar a lista
        qsort(lista, total, sizeof(UtilizadorInfo), compararUtilizadores);

        // Mostrar a lista ordenada
        for (int i = 0; i < total; i++) {
            // Monta a string do meio para contar o comprimento real
            char meio[100];
            snprintf(meio, sizeof(meio), "%s - %s", lista[i].tipo, lista[i].nome);

            // Calcula espaços à direita
            int len = strlen(meio);
            int espacos = 30 - len - 2; // -2 para as bordas "║ ║"
            if (espacos < 0) espacos = 0;

            printf("║ %s%*s ║\n", meio, espacos, "");
        }
    }

    printf("╚══════════════════════════════╝\n");
    printf("\nPressione Enter para continuar...");
    getchar();
    limparBuffer();
    menu_admin(sock, serverAddr, utilizador);
}

// Função para mostrar a versão do software
void verVersao(int sock, struct sockaddr_in serverAddr, const char *utilizador) {
    system("clear");
    pedirMenu(sock, serverAddr, "MENU:versao");
    printf("\nPressione Enter para continuar...");
    getchar();
    limparBuffer();
    menu_admin(sock, serverAddr, utilizador);
}
