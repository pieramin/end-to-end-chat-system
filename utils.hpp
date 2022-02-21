#include <openssl/evp.h>

typedef struct _users{
    char* name;
    EVP_PKEY* publickey;
    _users* next=NULL;
}Users;


typedef struct _clients
{
    char* name;
    int busy=0;
    int logged=0;
    unsigned char* client_server_symmetric_key;
    unsigned char* IV;
    int socket;
    int socket_dest;
    unsigned char* chat_sym_key; 
	unsigned char* chat_IV; 
    _clients* next=NULL;
} Clients;


void freeDatabase(Users* database);
Users* searchUser(char* string,Users* database);
Users* addUser(char* string, EVP_PKEY* pubkey, Users* database);
Users* LoadDatabase(char* path,Users* database);
void print_database(Users*);

Clients* verifyOnlineUser(char* string, Clients* list);
bool save_key(unsigned char*, unsigned char*, int, Clients*);
void set_logged(Clients*);
void print_clients(Clients*);
