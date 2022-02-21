#define nonce_length 12 
#define length_max_users 10   
#define aes_key_length 16 //dimensione della chiave AES utilizzata nella sessioni simmetriche 
#define session_value 0 
//valori per gli OPCODE 
#define CHAT 15

#define tag_size 16
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

int login_client(int,char*);
int quit_from_the_server();
int startchat();
int handshake_caller();
int am_i_chatting();
bool next_operation_for_server(int, uint32_t, int);
void change_state(int n);
bool recvCode(int socket, uint32_t* received_opcode, int sessione);
bool chat_request();
bool recvMessage();
bool sendMessage(char* read_message, uint32_t message_size);
bool show_online_clients();
