#include<utils.hpp>

//Crypto constants
#define aes_key_length 16 //dimensione della chiave AES utilizzata nella sessioni simmetriche 
#define nonce_length 12 
#define length_max_users 10     
#define DEBUGV 0 //se impostata ad 1 aiuta nel debug del programma stampando a video i buffer maneggiati 
//#define AES_DE_MODE EVP_aes_128_gcm() //modalità di AES utilizzata per il Digital Envelope
#define client_signature_length 384
#define session_value 0

//valori per gli OPCODE 
#define CHAT 15

#define tag_size 16



int login(int);
int init();
void disconnect_client(int s);
bool recvCode(int socket, uint32_t* received_opcode, int session_type);
Clients* get_client(int s);
bool end_chat(Clients* current_client);
bool on_clients( int c_socket);
int get_socket(char* name);
bool StartChat(int c1_socket, int* c2_socket, int* esito);
bool ClientHandshake(int c1_socket, int c2_socket);
bool ExchangeMessage(int c1_socket);
