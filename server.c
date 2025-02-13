#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fcntl.h>

#define PORT 2703

fd_set actfds;
typedef struct{
    char name[50];
    char pass[50];
    bool aut;
    int fd;
}user;
user* users = NULL;
int cnt; //numarul de utilizatori din json

typedef struct{
    unsigned char key[16];
    unsigned char iv[16];
}keys;
keys cbc[10];

typedef struct Node{
    char *com[20];
    char *opr;
    struct Node *left;
    struct Node *right;
} Node;
char *args[20][20] = {};

char* client_dir[10];

unsigned char key[16] = "dib3lw0.5i1g86n1";
unsigned char iv[16] = "[4k1;!o2sni90?ro";

char* read_json(const char* filename)
{
    long long l;
    char* fisier; 
    FILE* file = fopen(filename, "r");
    if(file == NULL)
    {
        perror("Eroare la deschiderea fisierului json");
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    l = ftell(file);
    fseek(file, 0, SEEK_SET);
    fisier = (char*)malloc(l + 1);
    if(fisier == NULL)
    {
        perror("Eroare alocare memorie");
        fclose(file);
        return NULL;
    }
    fread(fisier, sizeof(char), l, file);
    fisier[l] = '\0';
    fclose(file);
    return fisier;
}

bool transform(char* fisier)
{
    cJSON* root = cJSON_Parse(fisier);
    if(root == NULL)
    {
        perror("Eroare parsare json");
        return 0;
    }
    cJSON* v_users = cJSON_GetObjectItemCaseSensitive(root, "users");
    cnt = cJSON_GetArraySize(v_users);
    users = (user*)malloc(cnt * sizeof(user));
    if(users == NULL)
    {
        perror("Eroare alocare memorie");
        return 0;
    }

    for (int i = 0; i < cnt; i++) {
        cJSON* user_obj = cJSON_GetArrayItem(v_users, i);
        users[i].aut = 0;
        if (cJSON_IsObject(user_obj)) {
            cJSON* username = cJSON_GetObjectItemCaseSensitive(user_obj, "username");
            cJSON* password = cJSON_GetObjectItemCaseSensitive(user_obj, "password");

            if (cJSON_IsString(username) && (username->valuestring != NULL)) {
                strcpy(users[i].name, username->valuestring);
            }

            if (cJSON_IsString(password) && (password->valuestring != NULL)) {
                strcpy(users[i].pass, password->valuestring);
            }
        }
    }
    return 1;
}

int encrypt_decrypt(unsigned char key[16], unsigned char iv[16], const char* text, const int l, char* rez, int sau)
{
    EVP_CIPHER_CTX *ctx;
    int lrez = 0, total_l;
    if((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        perror("Eroare la crearea contextului");
        return 0;
    }
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, sau);
    EVP_CipherUpdate(ctx, rez, &lrez, text, l); 
    total_l = lrez;
    EVP_CipherFinal_ex(ctx, rez + total_l, &lrez); 
    total_l += lrez;
    if(sau == 0)
        rez[total_l] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return total_l;
}

int priority(char *op)
{
    if (strcmp(op, ";") == 0) return 1;
    if (strcmp(op, "&&") == 0 || strcmp(op, "||") == 0) return 2;
    if (strcmp(op, "|") == 0) return 3;
    if (strcmp(op, ">") == 0 || strcmp(op, "<") == 0 || strcmp(op, "2>") == 0) return 4;
    return 0;
}

Node* add(char *args[])
{
    Node* node = (Node*)malloc(sizeof(Node));
    if(priority(args[0]) == 0)
    {
        int i = 0;
        while(args[i] != NULL)
        {
            node->com[i] = args[i];
            i++; 
        }
        node->com[i] = NULL;
        node->opr = NULL;
    }
    else
    {
        node->com[0] = NULL;
        node->opr = args[0];
    }
    node->left = NULL;
    node->right = NULL;
    return node;
}

Node* build(char *args[20][20], int start, int end)
{
    if (start > end) return NULL;
    int min = 6;
    int index = -1;
    for (int i = start; i<= end; i++)
    {
        int pr = priority(args[i][0]);
        if (pr != 0 && pr <= min)
        {
            min = pr;
            index = i;
        }
    }

    if (index == -1)
        return add(args[start]);

    Node *root = add(args[index]);
    if (root == NULL)
        return NULL;
    root->left = build(args, start, index - 1);
    root->right = build(args, index + 1, end);
    return root;
}

int comcd(char* com[], int fd)
{
    if(com[2] != NULL)
    {
        char encrypted[50];
        int l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Too many arguments\n", 20, encrypted, 1);
        write(fd, &l, sizeof(int));
        write(fd, encrypted, l);
        return 1;
    }
    if (com[1] == NULL || strcmp(com[1], "~") == 0) 
        strcpy(client_dir[fd], getenv("HOME"));
    else if (com[1][0] == '/')
    {
        if(access(com[1], F_OK) == 0)
            strcpy(client_dir[fd], com[1]);
        else
        {
            char encrypted[50];
            int l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "cd: No such file or directory\n", 30, encrypted, 1);
            write(fd, &l, sizeof(int));
            write(fd, encrypted, l);
            while(client_dir[fd][strlen(client_dir[fd]) - 1] != '/')
                client_dir[fd][strlen(client_dir[fd]) - 1] = '\0';
            return 1; 
        }       
    }
    else
    {
        strcat(client_dir[fd], "/");
        strcat(client_dir[fd], com[1]);
    }
    if(access(client_dir[fd], F_OK) != 0)
    {
        char encrypted[50];
        int l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "cd: No such file or directory\n", 30, encrypted, 1);
        write(fd, &l, sizeof(int));
        write(fd, encrypted, l);
        while(client_dir[fd][strlen(client_dir[fd]) - 1] != '/')
            client_dir[fd][strlen(client_dir[fd]) - 1] = '\0';
        return 1;
    }
    return 0;
}

int execute(Node *root, int fd, int fderr, int path)
{
    char encrypted[1040];
    if (root == NULL) return 0;

    if (root->com[0] != NULL)
    {
        if(strcmp(root->com[0], "cd") == 0)
            return comcd(root->com, path);

        int PIPE[2];
        pipe(PIPE);

        pid_t pid = fork();

        if(pid > 0)
        {
            close(PIPE[1]);
            char rasp[1024];
            bzero(rasp, 0);
            int bytes;

            while((bytes = read(PIPE[0], rasp, 1023)) > 0)
            {
                bzero(encrypted, 1040);
                rasp[bytes] = '\0';
                if(fd != -1)
                {
                    bytes = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, rasp, bytes, encrypted, 1);
                    write(fd, &bytes, sizeof(int));
                    write(fd, encrypted, bytes);
                }
                else                
                    printf("%s", rasp);
            }
            close(PIPE[0]);
            int status;
            waitpid(pid, &status, 0);
            return WEXITSTATUS(status);
        }
        else   
        {
            close(PIPE[0]);
            dup2(PIPE[1], STDOUT_FILENO);
            if (fderr != 0)
                dup2(fderr, STDERR_FILENO);
            else
                dup2(PIPE[1], STDERR_FILENO);

            chdir(client_dir[path]);
            
            execvp(root->com[0], root->com);

            perror("Comanda gresita");
            exit(1);
        }         
    }
    else
    {
        if (strcmp(root->opr, "|") == 0)
        {
            int pipefd[2];
            if (pipe(pipefd) == -1) {
                perror("Eroare la crearea pipe-ului");
                return 1;
            }

            pid_t pid1 = fork();
            int status1 = -1;
            if (pid1 == 0) {
                close(pipefd[0]);  
                dup2(pipefd[1], STDOUT_FILENO);  
                dup2(pipefd[1], STDERR_FILENO); 
                close(pipefd[1]);  

                if (root->left->com[0] != NULL) {
                    chdir(client_dir[path]);
                    execvp(root->left->com[0], root->left->com);
                    perror("Eroare la execvp (stânga)");
                    exit(1);
                } else {
                    status1 = execute(root->left, -1, 0, fd);  
                    exit(status1);
                }
            }

            pid_t pid2 = fork();

            int status2 = -1;
            if (pid2 == 0) {
                close(pipefd[1]);  
                dup2(pipefd[0], STDIN_FILENO);  
                dup2(pipefd[0], STDERR_FILENO);
                close(pipefd[0]);  

                if (root->right->com[0] != NULL) {
                    int PIPE[2];
                    pipe(PIPE);

                    pid_t pid = fork();

                    if (pid > 0) {
                        close(PIPE[1]);
                        char rasp[1024];
                        bzero(rasp, 0);
                        int bytes;

                        while ((bytes = read(PIPE[0], rasp, 1023)) > 0) 
                        {
                            bzero(encrypted, 1040);
                            rasp[bytes] = '\0';
                            bytes = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, rasp, bytes, encrypted, 1);
                            write(fd, &bytes, sizeof(int));
                            write(fd, encrypted, bytes);
                        }
                        close(PIPE[0]);
                        int status;
                        waitpid(pid, &status, 0);
                        exit(WEXITSTATUS(status));

                    } else {
                        close(PIPE[0]);
                        dup2(PIPE[1], STDOUT_FILENO);
                        dup2(PIPE[1], STDERR_FILENO);
                        chdir(client_dir[path]);
                        execvp(root->right->com[0], root->right->com);

                        perror("Eroare la execvp (dreapta)");
                        exit(1);
                    }
                } else {
                    status2 = execute(root->right, fd, 0, fd);  
                    exit(status2);
                }
            }

            close(pipefd[0]);
            close(pipefd[1]);
            waitpid(pid1, &status1, 0);  
            waitpid(pid2, &status2, 0);  

            if (WIFEXITED(status1) && WIFEXITED(status2)) 
                return (WEXITSTATUS(status1) == 0 && WEXITSTATUS(status2) == 0) ? 0 : 1;
        }

        if (strcmp(root->opr, "||") == 0)
        {
            if(execute(root->left, fd, 0, fd) != 0)
                return execute(root->right, fd, 0, fd);
            return 0;

        }
        if (strcmp(root->opr, "&&") == 0)
        {
            if(execute(root->left, fd, 0, fd) == 0)
                return execute(root->right, fd, 0, fd);
            return 1;
        }
        if (strcmp(root->opr, ";") == 0)
        {
            execute(root->left, fd, 0, fd);
            return execute(root->right, fd, 0, fd);
        }
        if (strcmp(root->opr, "<") == 0)
        {
            char path[1024];
            strcpy(path, client_dir[fd]);
            strcat(path, "/");
            strcat(path, root->right->com[0]);
            int fd_in = open(path, O_RDONLY);
            if (fd_in == -1)
            {
                char encrypted[50];
                int l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Eroare deschidere fișier input\n", 32, encrypted, 1);
                write(fd, &l, sizeof(int));
                write(fd, encrypted, l);
                return 1;                
            }

            dup2(fd_in, STDIN_FILENO);
            close(fd_in);

            execute(root->left, fd, 0, fd);
            return 0;
        }

        if (strcmp(root->opr, ">") == 0)
        {
            char path[1024];
            strcpy(path, client_dir[fd]);
            strcat(path, "/");
            strcat(path, root->right->com[0]);
            int fd_out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_out == -1)
            {
                char encrypted[50];
                int l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Eroare deschidere fișier output\n", 33, encrypted, 1);
                write(fd, &l, sizeof(int));
                write(fd, encrypted, l);
                return 1;   
            }

            int outp = dup(STDOUT_FILENO);
            dup2(fd_out, STDOUT_FILENO);
            close(fd_out);

            execute(root->left, -1, 0, fd);
            dup2(outp, STDOUT_FILENO);
            close(outp);
            return 0;
        }

        if (strcmp(root->opr, "2>") == 0)
        {
            char path[1024];
            strcpy(path, client_dir[fd]);
            strcat(path, "/");
            strcat(path, root->right->com[0]);
            int fd_out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_out == -1)
            {
                char encrypted[50];
                int l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Eroare deschidere fișier output\n", 33, encrypted, 1);
                write(fd, &l, sizeof(int));
                write(fd, encrypted, l);
                return 1;   
            }

            execute(root->left, fd, fd_out, fd);
            return 0;
        }
    }
}

int mesaj(int fd)
{
    char encrypted[1040];
    int bytes;			
    char msg[1024];		
    int l, lng;
    bzero(encrypted, 1040);
    bzero(msg, 1024);
    bytes = read(fd, &lng, sizeof(int));
    read(fd, encrypted, lng);
    l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, encrypted, lng, msg, 0);
    if (bytes < 0)
    {
        perror ("Eroare la read() de la client.\n");
        return 0;
    }
    if (bytes == 0)
    {
        close (fd);		
        FD_CLR (fd, &actfds);
        int i = 0;
        while(i <= cnt)
        {
            if(users[i].fd == fd)
            {
                users[i].aut = 0;
                users[i].fd = 0;
                break;
            }
            i++;
        }
        printf ("[server] S-a deconectat clientul cu descriptorul %d.\n",fd);
        fflush (stdout);
        return 0;
    }
    if(strcmp(msg, "Conectare") == 0)
    {
        char name[50], pass[50];
        bzero(encrypted, 1040);
        bzero(name, 50);
        bzero(pass, 50);
        read(fd, &l, sizeof(int));
        read(fd, encrypted, l);
        encrypt_decrypt(cbc[fd].key, cbc[fd].iv, encrypted, l, name, 0);
        bzero(encrypted, 1040);
        read(fd, &l, sizeof(int));
        read(fd, encrypted, l);
        encrypt_decrypt(cbc[fd].key, cbc[fd].iv, encrypted, l, pass, 0);
        for(int i = 0; i < cnt; i++)
        {
            if(strcmp(name, users[i].name) == 0)
            {
                if(users[i].aut == 1)
                {
                    bzero(encrypted, 1040);
                    l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Utilizator deja conectat", 24, encrypted, 1);
                    write(fd, &l, sizeof(int));
                    write(fd, encrypted, l);
                    return 0;
                }
                if(strcmp(pass, users[i].pass) == 0)
                {
                    bzero(encrypted, 1040);
                    l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Conectare cu succes", 19, encrypted, 1);
                    write(fd, &l, sizeof(int));
                    write(fd, encrypted, l);
                    users[i].aut = 1;
                    users[i].fd = fd;
                    return 1;                    
                }
                else
                {
                    bzero(encrypted, 1040);
                    l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Parola gresita", 14, encrypted, 1);
                    write(fd, &l, sizeof(int));
                    write(fd, encrypted, l);
                    return 0;                    
                }                
            }
        }
        bzero(encrypted, 1040);
        l = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Utilizatorul nu exista", 22, encrypted, 1);
        write(fd, &l, sizeof(int));
        write(fd, encrypted, l);
        return 0;        
    }

    msg[l - 1] = '\0';
    if (msg[0] == '\0')
    {
        l = 4;
        write(fd, &l, sizeof(int));
        write(fd, "DONE", l);    
        return 0;   
    }
    for(int i = 0; i < strlen(msg) - 1; i++)
    {
        if((msg[i] == '|' && msg[i + 1] == '|') || (msg[i] == '&' && msg[i + 1] == '&') || (msg[i] == '2' && msg[i+1] == '>'))
        {
            if(i + 1 != strlen(msg) - 1)
            {
                char aux[1024];
                strcpy(aux, msg + i - 1);
                strcpy(msg + i, aux);
                msg[i] = ' ';
                strcpy(aux, msg + i + 3);
                strcpy(msg + i + 4, aux);
                msg[i + 3] = ' ';
                i = i + 3;      
            }
            continue;      
        }
        if(msg[i] == '<' || msg[i] == ';' || msg[i] == '|' || msg[i] == '>')
        {
            char aux[1024];
            strcpy(aux, msg + i - 1);
            strcpy(msg + i, aux);
            msg[i] = ' ';
            strcpy(aux, msg + i + 2);
            strcpy(msg + i + 3, aux);
            msg[i + 2] = ' ';
            i = i + 2;
        }
    }

    printf("[server] Comanda este...%s\n",msg);
    fflush(stdout);

    char oper[7][3] = {"||", "<", "2>", ">", "&&", "|", ";"};
    char *str = strtok(msg, " ");
    int i = 0, j = 0;
    while(str != NULL)
    {
        int ok = 0;
        for(int k = 0;k < 7;k++)
            if(strcmp(str, oper[k]) == 0)
            {
                if(i % 2 == 0 && j == 0)
                {
                    int bytes = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Comanda gresita\n", 16, encrypted, 1);
                    write(fd, &bytes, sizeof(int));
                    write(fd, encrypted, bytes);   
                    l = 4;
                    write(fd, &l, sizeof(int));
                    write(fd, "DONE", l);         
                    return 0;  
                }
                args[i][j] = NULL;
                i++;
                args[i][0] = str;
                i++;
                j = 0;
                ok = 1;
            }
        if (ok == 0)
        {
            args[i][j] = str;
            j++;
        } 
        str = strtok(NULL, " ");
    }
    args[i][j] = NULL;

    if (j == 0)
    {
        if(strcmp(args[i - 1][0], ";") == 0)
            i = i - 2;
        else
        {
            int bytes = encrypt_decrypt(cbc[fd].key, cbc[fd].iv, "Comanda incompleta\n", 19, encrypted, 1);
            write(fd, &bytes, sizeof(int));
            write(fd, encrypted, bytes); 
            l = 4;
            write(fd, &l, sizeof(int));
            write(fd, "DONE", l);          
            return 0;              
        }
    }

    Node* root = build(args, 0, i);

    execute(root, fd, 0, fd);
    l = 4;
    write(fd, &l, sizeof(int));
    write(fd, "DONE", l);    
    return 0;   
}

int main()
{
    struct sockaddr_in server;	
    struct sockaddr_in from;
    fd_set readfds;	
    struct timeval tv;		
    int sd, client, fd;		
    int optval=1; 			
    int nfds;			
    int len;	

    char* fisier = read_json("users.json");
    if(fisier == NULL)
        return 4;

    if(transform(fisier) == 0)
        return 5;

    if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror ("[server] Eroare la socket()");
        return 1;
    }
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,&optval,sizeof(optval)); 

    bzero (&server, sizeof (server));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl (INADDR_ANY);
    server.sin_port = htons (PORT);

    if (bind (sd, (struct sockaddr *) &server, sizeof (struct sockaddr)) == -1)
    {
        perror ("[server] Eroare la bind()");
        return 2;
    }
    if (listen (sd, 5) == -1)
    {
        perror ("[server] Eroare la listen().\n");
        return 3;
    }
    
    FD_ZERO (&actfds);		
    FD_SET (sd, &actfds);		

    tv.tv_sec = 1;		
    tv.tv_usec = 0;
    
    nfds = sd;

    printf ("[server] Asteptam la portul %d...\n", PORT);
    fflush (stdout);


    while (1)
    {
        bcopy ((char *) &actfds, (char *) &readfds, sizeof (readfds));

        if (select (nfds+1, &readfds, NULL, NULL, &tv) < 0)
        {
            perror ("[server] Eroare la select().\n");
            return 6;
        }
        if (FD_ISSET (sd, &readfds))
        {
            len = sizeof (from);
            bzero (&from, sizeof (from));

            client = accept (sd, (struct sockaddr *) &from, &len);

            if (client < 0)
            {
                perror ("[server] Eroare la accept().\n");
                continue;
            }

            if (nfds < client)
                nfds = client;

            bzero(cbc[client].key, 16);
            bzero(cbc[client].iv, 16);
            RAND_bytes(cbc[client].key, 16);
            RAND_bytes(cbc[client].iv, 16);
            char key_encrypt[128] = {0};
            char iv_encrypt[128] = {0};
            int l_key = encrypt_decrypt(key, iv, cbc[client].key, 16, key_encrypt, 1);
            int l_iv = encrypt_decrypt(key, iv, cbc[client].iv, 16, iv_encrypt, 1);
            write(client, &l_key, sizeof(int));
            write(client, key_encrypt, l_key);
            write(client, &l_iv, sizeof(int));
            write(client, iv_encrypt, l_iv);

            client_dir[client] = (char *)malloc(100 * sizeof(char));
            getcwd(client_dir[client], 100);

            FD_SET (client, &actfds);

            printf("[server] S-a conectat clientul cu descriptorul %d\n",client);
            fflush (stdout);
        }
        for (fd = 0; fd <= nfds; fd++)	
        {
            if (fd != sd && FD_ISSET (fd, &readfds))
            {	
                mesaj(fd);
            }
        }			
    }				
}