#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int port;
int sd;	
unsigned char key[16], iv[16];
unsigned char public_key[16] = "dib3lw0.5i1g86n1";
unsigned char public_iv[16] = "[4k1;!o2sni90?ro";

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


void autentificare()
{
    char name[100], pass[100], encrypted[1040];
    int l, lng;
    printf("[client] Introduceti username: ");
    fflush(stdout);
    bzero(name, 100);
    read(0, name, 100);   
    name[strlen(name) - 1] = '\0';      
    printf("[client] Introduceti parola: ");
    fflush(stdout);    
    bzero(pass, 100);
    read(0, pass, 100);
    pass[strlen(pass) - 1] = '\0';      

    bzero(encrypted, 1040);
    l = encrypt_decrypt(key, iv, "Conectare", 9, encrypted, 1);
    write(sd, &l, sizeof(int));
    write(sd, encrypted, l);
    bzero(encrypted, 1040);
    lng = strlen(name);
    l = encrypt_decrypt(key, iv, name, lng, encrypted, 1);
    write(sd, &l, sizeof(int));
    write(sd, encrypted, l);
    bzero(encrypted, 1040);
    lng = strlen(pass);
    l = encrypt_decrypt(key, iv, pass, lng, encrypted, 1);
    write(sd, &l, sizeof(int));
    write(sd, encrypted, l);

    char rasp[128];
    bzero(encrypted, 1040);
    read(sd, &l, sizeof(int));
    read(sd, encrypted, l);
    encrypt_decrypt(key, iv, encrypted, l, rasp, 0);
    printf("[client] %s\n", rasp);
    fflush(stdout);      

    if(strcmp(rasp, "Utilizatorul nu exista") == 0 || strcmp(rasp, "Utilizator deja conectat") == 0 || strcmp(rasp, "Parola gresita") == 0)
        autentificare();
}

int main (int argc, char *argv[])
{

    struct sockaddr_in server;	 
    char msg[1024];		
    if (argc != 3)
    {
        printf ("[client] Sintaxa: %s <adresa_server> <port>\n", argv[0]);
        return -1;
    }

    port = atoi (argv[2]);

    if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror ("[client] Eroare la socket().\n");
        return 1;
    }
    

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons (port);
    
    if (connect (sd, (struct sockaddr *) &server,sizeof (struct sockaddr)) == -1)
    {
        perror ("[client] Eroare la connect().\n");
        return errno;
    }
    
    int l;
    unsigned char key_encrypt[128];
    unsigned char iv_encrypt[128];
    read(sd, &l, sizeof(int));
    read(sd, key_encrypt, l);
    encrypt_decrypt(public_key, public_iv, key_encrypt, l, key, 0);
    read(sd, &l, sizeof(int));
    read(sd, iv_encrypt, l);
    encrypt_decrypt(public_key, public_iv, iv_encrypt, l, iv, 0);

    autentificare();
    while(1)
    {
        bzero (msg, 1024);
        printf ("[client] Introduceti o comanda: ");
        fflush (stdout);
        read (0, msg, 1024);
        
        char msg_encrypt[1040], rasp_descrypt[1040];
        bzero(msg_encrypt, 1040);
        int l = encrypt_decrypt(key, iv, msg, strlen(msg), msg_encrypt, 1);
        write(sd, &l, sizeof(int));
        if (write (sd, msg_encrypt, l) <= 0)
        {
            perror ("[client] Eroare la write() spre server.\n");
            return errno;
        }        

        char rasp[1024];
        bzero(rasp, 1024);
        read(sd, &l, sizeof(int));
        read(sd, rasp, l);
        while(strcmp(rasp, "DONE") != 0)
        {
            bzero(rasp_descrypt, 1040);
            encrypt_decrypt(key, iv, rasp, l, rasp_descrypt, 0);
            printf("%s", rasp_descrypt);
            read(sd, &l, sizeof(int));
            bzero(rasp, 1024);
            read(sd, rasp, l);
        }
    }
}