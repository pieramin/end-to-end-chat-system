#include<iostream>
#include<crypto.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <cstring>
#include <string>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

//this is the list of the clients.
Clients* clients=NULL;

//contiene la chiave pubblica e i nomi associati degli utenti registrati
Users* database;

EVP_CIPHER_CTX* ctx; 

//utility functions
int create_temp_rsa_key(EVP_PKEY *newSK);
bool create_nonce(unsigned char* nonce);
bool transmit_data(int socket, unsigned char *data, uint32_t data_length);
bool receive_data(int socket, unsigned char *&data, uint32_t data_length);
int envelope_decrypt(unsigned char *ciphertext, int cipher_len, EVP_PKEY* privkey, unsigned char *iv, unsigned char *plaintext, unsigned char* en_key, int en_key_size);
bool send_uint(int socket, uint32_t num);
int init();
void init_new_client(Clients* curr, char* name, int c_socket);
void inc_iv(int session_type, Clients* current_client);
void increment(unsigned char* buffer, uint32_t size);
void disconnect_client(int s);
bool recvCode(int socket, uint32_t* received_opcode, int session_type);
Clients* get_client(int s);
void change_state(Clients* current_client,int code);
bool sendCode(int socket, uint32_t opcode, int session_type);
bool sendAutData(int socket, unsigned char* data, int data_size, Clients* current_client);
bool end_chat(Clients* current_client);
bool on_clients( int c_socket);
bool recvSecureData(int socket, unsigned char* data, uint32_t data_size, int session_type);
bool recvAutData(int socket, unsigned char* data, int data_size, int session_type);
int get_socket(char* name);
bool StartChat(int c1_socket, int* c2_socket, int* esito);
bool ClientHandshake(int c1_socket, int c2_socket);
bool ExchangeMessage(int c1_socket);




//return 0 if the operation succeds, -1 otherwise
int login(int c_socket){
	

//Creazione e invio del messaggio di autenticazione (M2)
    uint32_t clear_message_size; 
	uint32_t total_message_size; 
	uint32_t signed_message_size;
	uint32_t server_sign_size; 
	uint32_t server_cert_size; 
	uint32_t client_sign_size;
//buffer per la ricezione dei messaggi e dimensioni 
	unsigned char* c_clear_message, *s_clear_message;
	unsigned char* c_total_message, *s_total_message; 
	unsigned char* s_signed_message; 
	unsigned char* server_sign;
	unsigned char* client_sign; 
	char* client_name;
	unsigned char* temp_nonce; 
	unsigned char* client_nonce; 
	unsigned char* server_nonce; 

//ricezione messaggio dal client (client_nonce || client_name )
	
	//strutture dati per il messaggio da ricevere
	client_nonce = (unsigned char*)malloc(nonce_length);
	server_nonce = (unsigned char*)malloc(nonce_length);
	temp_nonce = (unsigned char*)malloc(nonce_length);

	total_message_size = nonce_length + length_max_users; 
	c_total_message = (unsigned char*)malloc(total_message_size); 
	client_name = (char*)malloc(length_max_users); 
	
	//ricezione messaggio 
	if(!receive_data(c_socket, c_total_message, total_message_size)){
		cerr << " Error receiving the auth message from the client" << endl; 
		return -1; 
	}
	
	//immissione nei buffer dei dati nel messaggio 
	memcpy(client_nonce, c_total_message, nonce_length); 
	memcpy(client_name, c_total_message + nonce_length, length_max_users); 
	
	OPENSSL_free(c_total_message); 
	
	//verifica client  
	if(searchUser(client_name,database)==NULL) cerr<<"User not registered";
	
	
	//TODO VERIFICA SE UTENTE E' GIA LOGGATO (ATTIVO) AL SERVER
	if(verifyOnlineUser(client_name,clients)!=NULL){
		cerr<<"User already online";
		if(!send_uint(c_socket, -1)){
			cerr << "Error send uint" << endl; 
			return -1; 
		}
		return -1;
	} 
	
	//warning: unsafe
	Clients* new_client=(Clients*)malloc(sizeof(Clients));
	init_new_client(new_client,client_name,c_socket);
	Clients* iterator=clients;
	if(iterator==NULL) clients=new_client;
	else{
		while (iterator->next!=NULL) iterator=clients->next;
		iterator->next=new_client;
	}

    //caricamento certificato
	X509* certification; 
    FILE* certification_file = fopen("./server/certificate/server_cert.pem","r"); 
    certification = PEM_read_X509(certification_file, NULL, NULL,NULL);
    if(!certification){
		cerr <<"Error while opening certificate" << endl;
		return -1;
	}
		

    //serializzazione certificato
	unsigned char* serialized_cert = NULL; 
	server_cert_size = i2d_X509(certification, &serialized_cert);
	X509_free(certification); 

	//invio dimensione certificato 
	if(!send_uint(c_socket, server_cert_size)){
		cerr << "Error sending the certificate" << endl; 
		return -1; 
	}
	
    //generazione nonce
    if(!create_nonce(server_nonce)){
		cerr << "Error create_nonce()" << endl; 
		return -1; 
	}
	
	    //creazione coppia chiavi ephemeral
	EVP_PKEY* Tprivk = EVP_PKEY_new(); 
	char* Tpubkey = NULL; 
	
	if(!create_temp_rsa_key(Tprivk)){
		cerr << "Errorgenerating the eph keys" << endl; 
		return -1; 
	}
	
	BIO* Tpubkeybio = BIO_new(BIO_s_mem()); 
	PEM_write_bio_PUBKEY(Tpubkeybio, Tprivk); 
	long Tpubkey_size = BIO_get_mem_data(Tpubkeybio, &Tpubkey); 

    //caricamento chiave privata per firma
    EVP_PKEY* server_privkey = NULL; 
	string server_key_file_name = "./server/database/server_private.pem";
	FILE* server_key_file = fopen(server_key_file_name.c_str(), "r"); 
	if(!server_key_file){
		cerr << "error while opening the server private key" << endl; 
		return -1; 
	}

	server_privkey = PEM_read_PrivateKey(server_key_file, NULL, NULL,(void*) "1234"); 
	if(!server_privkey){
		cerr <<"error while opening the server private key"<<endl; 
		return -1; 
	}
	fclose(server_key_file); 
	server_sign_size = EVP_PKEY_size(server_privkey); 

   //strutture dati per il messaggio da inviare
	clear_message_size = nonce_length + server_cert_size + Tpubkey_size;
	total_message_size = clear_message_size + server_sign_size;
	signed_message_size = Tpubkey_size + nonce_length; 
    s_total_message = (unsigned char*)malloc(total_message_size);
	s_clear_message = (unsigned char*)malloc(clear_message_size); 
	s_signed_message = (unsigned char*)malloc(signed_message_size); 
	server_sign = (unsigned char*)malloc(server_sign_size); 

    //creazione messaggio in chiaro 
	memcpy(s_clear_message, server_nonce, nonce_length); 
	memcpy(s_clear_message + nonce_length, Tpubkey, Tpubkey_size); 
	memcpy(s_clear_message + Tpubkey_size + nonce_length, serialized_cert, server_cert_size); 
	memcpy(s_signed_message, Tpubkey, Tpubkey_size); 
	memcpy(s_signed_message + Tpubkey_size, client_nonce, nonce_length); 

    //creazione firma
	EVP_MD_CTX* ctx_server_sign = EVP_MD_CTX_new(); 
	EVP_SignInit(ctx_server_sign, EVP_sha256()); 
	EVP_SignUpdate(ctx_server_sign, s_signed_message, signed_message_size); 
	EVP_SignFinal(ctx_server_sign, server_sign, &server_sign_size, server_privkey); 
	EVP_MD_CTX_free(ctx_server_sign); 
	EVP_PKEY_free(server_privkey); 
	
	//unione parti del messaggio
	memcpy(s_total_message, s_clear_message, clear_message_size); 
	memcpy(s_total_message + clear_message_size, server_sign, server_sign_size); 
	



	//invio messaggio 
	if(!transmit_data(c_socket, s_total_message, total_message_size)){
		cerr << "Error with authentication" << endl; 
		return -1; 
	} 
	
	OPENSSL_free(s_total_message); 
	OPENSSL_free(server_sign); 
	OPENSSL_free(s_clear_message);

	//fino qui ok

	//ricezione messaggio finale protocollo RSAE (server_nonce || IV  || E_Tpubkey(key) || E_Tpubkey(aes_key) || DS)

	//creazione e dimensioanmento buffer per ricezione messaggio 
	uint32_t IV_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm()); 
	uint32_t en_key_size = server_sign_size; 
	client_sign_size = client_signature_length; 
	clear_message_size = nonce_length + IV_size + aes_key_length + en_key_size; 
	total_message_size = clear_message_size + client_sign_size;

	unsigned char* IV = (unsigned char*)malloc(IV_size); 
	unsigned char* aes_key = (unsigned char*)malloc(aes_key_length); 
	unsigned char* crypted_aes_key = (unsigned char*)malloc(aes_key_length); 
	unsigned char* en_key = (unsigned char*)malloc(en_key_size);  
	c_clear_message = (unsigned char*)malloc(clear_message_size); 
	c_total_message = (unsigned char*)malloc(total_message_size); 
	client_sign = (unsigned char*)malloc(client_sign_size); 
	
	//ricezione messaggio 
	if(!receive_data(c_socket, c_total_message, total_message_size)){
		cerr << " Error while receiving the message from the client" << endl; 
		return -1; 
	}
	
	//controllo nonce
	memcpy(temp_nonce, c_total_message, nonce_length); 
	if(memcmp(temp_nonce, server_nonce, nonce_length)){
		cerr << "Error verifing the nonce" << endl; 
		return -1; 
	}
	create_nonce(server_nonce); 
	
	//inserimento valori nei buffer
	memcpy(c_clear_message, c_total_message, clear_message_size); 
	memcpy(IV, c_total_message + nonce_length, IV_size); 
	memcpy(en_key, c_total_message + nonce_length + IV_size, en_key_size); 
	memcpy(crypted_aes_key, c_total_message + nonce_length + IV_size + en_key_size, aes_key_length); 
	memcpy(client_sign, c_total_message + clear_message_size, client_sign_size); 
	
	//reperimento chiave pubblica client 
	Users* curr=searchUser(client_name,database);
	if(curr==NULL) exit(1);
	EVP_PKEY* client_pubkey = curr->publickey; 
	
	//verifica firma
	EVP_MD_CTX* client_sign_ctx = EVP_MD_CTX_new(); 
	EVP_VerifyInit(client_sign_ctx, EVP_sha256());
	EVP_VerifyUpdate(client_sign_ctx, c_clear_message, clear_message_size);
	int ret = EVP_VerifyFinal(client_sign_ctx, client_sign, client_sign_size, client_pubkey);
	if(ret != 1){
		cerr << "error verifing the client signature" << endl; 
		EVP_MD_CTX_free(client_sign_ctx); 
		return -1; 
	}
	EVP_MD_CTX_free(client_sign_ctx); 


	//estrazione chiave simmetrica 

	
	uint32_t envelope_size = envelope_decrypt(crypted_aes_key, aes_key_length, Tprivk, IV, aes_key, en_key, en_key_size); 
	if(save_key(aes_key,IV,0,new_client)){
		set_logged(new_client);
		cout << "Established session with the client: : " << client_name << endl; 

	}
	 else{
		 cerr<<"Error while saving the key, the session is not established";
	 }
	
	
    return 0;
}

int create_temp_rsa_key(EVP_PKEY *newSK){
    int ret;
    RSA* r;
   
    BIGNUM * bn = 0;
    bn = BN_new();
    BN_set_word(bn, 65537);
   
    r = RSA_new();
   
    ret = RSA_generate_key_ex(r, 2048, bn, NULL);
    if(!ret) {
        cerr << "error while generating the rsa key ex " << endl;
        return false;
    }
   
    ret = EVP_PKEY_assign_RSA(newSK, r);
    if(!ret){
        cerr << "error EVP_PKEY_assign_RSA" << endl;
        return false;
    }
    return true;
}

bool create_nonce(unsigned char* nonce){

	RAND_poll();
	int ret = RAND_bytes(nonce, nonce_length); 
	if(!ret){
		cerr << "error generating the nonce" << endl; 
		return false; 
	}
	
	return true; 
}

bool transmit_data(int socket, unsigned char *data, uint32_t data_length){

	if(send(socket, (void*) data, data_length, 0) <= 0 || send(socket, (void*) data, data_length, 0) != (int)data_length){ 
		cerr << "Error while transmitting - transmit_data" << endl;
		return false;
	}

	return true;
}

//ricezione di dati
bool receive_data(int socket, unsigned char *&data, uint32_t data_length){

	if(recv(socket, (void*) data, data_length, 0) <= 0 || recv(socket, (void*) data, data_length, 0) != (int)data_length){ 
		cerr << "Error receiving data in recvData" << endl;
		return false;
	}

	return true;
}

//funzione per il decriptaggio simmetrico 
int envelope_decrypt(unsigned char *ciphertext, int cipher_len, EVP_PKEY* privkey,
  unsigned char *iv, unsigned char *plaintext, unsigned char* en_key, int en_key_size){
	  
	  int len;
	  int plain_len, ret;
	  EVP_CIPHER_CTX* ctx; 

	  /* Create and initialise the context */
	  ctx = EVP_CIPHER_CTX_new();
	  
	  
	  // SealInit
	  ret = EVP_OpenInit(ctx, EVP_aes_128_gcm(), en_key, en_key_size, iv, privkey);
	  if(!ret){
		 cout << "error in OpenInit" << endl; 
		 return 0; 
	  }
	 
	  EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, cipher_len);
	  plain_len = len;

	  //Encrypt Final. Finalize the encryption and adds the padding
	  EVP_OpenFinal(ctx, plaintext + len, &len);
	  plain_len += len;
	  
	  // MUST ALWAYS BE CALLED!!!!!!!!!!
	  EVP_CIPHER_CTX_free(ctx);

	  return plain_len;
}

bool send_uint(int socket, uint32_t num){
	int result;
	uint32_t num_s;
	
	num_s = htonl(num); //da host order a network order

	result = send(socket, (void*) &num_s, sizeof(num_s), 0);
	if(result < 0 || result!=sizeof(num_s)){ 
		cerr << "Error sending di uint32_t" << endl;
		return false;
	}

	return true;
}

void init_new_client(Clients* curr, char* name, int c_socket){
	curr->name=name;
    curr->busy=0;
    curr->logged=0;
    curr->client_server_symmetric_key=NULL;
    curr->IV=NULL;
    curr->socket=c_socket;
    curr->socket_dest=0;
    curr->chat_sym_key=NULL; 
	curr->chat_IV=NULL; 
    curr->next=NULL;
}



int init(){
	database=LoadDatabase((char*)"./server/database/users/", database);
	return 0;
}

void disconnect_client(int s){
	Clients* curr=clients;
	Clients* prec=NULL;
	while(curr!=NULL){
		if(curr->socket==s){
			if(prec==NULL){
				Clients* tmp=curr->next;
				free(curr);
				clients=tmp;
			}
			else{
				prec->next=curr->next;
				free(curr);
			}
		}
		prec=curr;
		curr=curr->next;
	}
}

Clients* get_client(int s){ 
	Clients* curr=clients;
	while(curr!=NULL){
		if(curr->socket==s){
			return curr;
		}
		curr=curr->next;
	}
	return NULL;
}

int get_socket(char* name){ 
	Clients* curr=clients;
	while(curr!=NULL){
		if(strncmp(name,curr->name,strlen(name))==0){
			return curr->socket;
		}
		curr=curr->next;
	}
	return -1;
}

//riceve e gestisce il messaggio (seq_number || E(aes_key, opcode) || TAG)
bool recvCode(int socket, uint32_t* received_opcode, int session_type){
	
	int ret; 
	Clients* current_client=get_client(socket);
	//preparazione dei buffer per la ricezione del messaggio e 
	// per il decriptaggio 
	uint32_t plain_size = sizeof(uint32_t); 
	uint32_t cipher_size = plain_size; 
	uint32_t total_size = nonce_length + cipher_size + 16;	
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
	unsigned char* plaintext = (unsigned char*)malloc(plain_size); 
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_size);
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(nonce_length);
	unsigned char* received_seq_number = (unsigned char*)malloc(nonce_length);
	
	//ricezione messaggio
	ret = recv(socket, (void*) total_message, total_size, 0);
	if(ret <= 0 || ret != (int)total_size){ 
		cerr << "Error receiving recv" << endl;
		return false;
	}
	

	 
	//copio i valori nei buffer
	memcpy(aad, total_message, nonce_length); 
	memcpy(ciphertext, total_message + nonce_length, cipher_size);
	memcpy(tag, total_message + nonce_length + cipher_size, 16); 
	memcpy(received_seq_number, total_message, nonce_length); 
	
	//incremento IV e lo carico per controllare il numero ricevuto 
	inc_iv(session_type,current_client);
//generazione oggetto per la codifica

if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no session key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "no iv between client server" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client server" << endl; 
			return false;
		}
	}
	else{
		if(!current_client->chat_sym_key){
			cerr << "no session key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "no iv between client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}		
	
	//valuto se il numero di sequenza ricevuto è corretto
	if(memcmp(received_seq_number, IV, nonce_length)){
		cerr << "wrong sequence number received" << endl; 
		return false; 
	}
	
	
	//decriptaggio plaintext 	
	int len; 
	int plaintext_len; 
	
	//inizializzazione contesto 
	ctx = EVP_CIPHER_CTX_new(); 
	
	EVP_DecryptInit(ctx, EVP_aes_128_gcm(),aes_key, IV);
	
	EVP_DecryptUpdate(ctx, NULL, &len, aad, nonce_length);
	
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_size);
	plaintext_len = len; 
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) ;

	ret = EVP_DecryptFinal(ctx, plaintext + len, &len);
	if(!ret){
		cerr << "Errore nella Decrypt Final" << endl; 
		return false; 
	}
	plaintext_len += len; 

	EVP_CIPHER_CTX_free(ctx); 	
	if(plaintext_len!=plain_size){
		cerr << "Error" << endl;
		return false; 
	}
	
	
	//copio valore opcode ricevuto 
	memcpy(received_opcode, plaintext, plain_size); 
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key);
	OPENSSL_free(plaintext);
	OPENSSL_free(ciphertext);
	
	return true; 
}

void inc_iv(int session_type, Clients* current_client){
	unsigned char* IV = (unsigned char*)malloc(nonce_length); 
	
	if(session_type == session_value){
		
		memcpy(IV, current_client->IV, nonce_length); 
		increment(IV, nonce_length); 
		
		memcpy(current_client->IV, IV, nonce_length); 
	}
	else{
		memcpy(IV, current_client->chat_IV, nonce_length); 
		increment(IV, nonce_length); 
		memcpy(current_client->chat_IV, IV, nonce_length); 
	}
}

//funzione per incrementare un buffer binario 
void increment(unsigned char* buffer, uint32_t size){

		uint32_t index = size - 1;
		
		buffer[index]++; 
		
		if(!buffer[index] && index){
			increment(buffer, index); 
		}
}

bool end_chat(Clients* current_client){
	
	printf("closing the chat");
	int c1_socket = current_client->socket; 
	int c2_socket = current_client->socket_dest; 

	Clients* dest=get_client(c2_socket);

	if(!sendCode(c2_socket, 4, session_value)){
		cerr << "Error closing the chat" << endl; 
		return false; 
	}
	
	if(!sendCode(c1_socket, 4, session_value)){
		cerr << "Error closing the chat" << endl; 
		return false; 
	}
	
	change_state(current_client,0); 
	change_state(dest,0); 

	return true; 
}

void change_state(Clients* current_client,int code){
	current_client->busy=code;
}

//funzione che invia il codice della prossima operazione richiesta al server dal client 
//compone il messaggio (seq_number || Ek(opcode) || TAG)
bool sendCode(int socket, uint32_t opcode, int session_type){
	
	Clients* current_client=get_client(socket);
	int ret; 
	
	//preparazione del messaggio da criptare 
	uint32_t plain_size = sizeof(uint32_t); 
	uint32_t cipher_size = plain_size; 
	uint32_t total_size = nonce_length + cipher_size + 16; 
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
	unsigned char* plaintext = (unsigned char*)malloc(plain_size); 
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_size);
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(nonce_length);
	
	//Incremento numero di sequenza 
	inc_iv(session_type,current_client);
	
	//generazione oggetto per la codifica
//generazione oggetto per la codifica

if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no session key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "no iv between client server" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client server" << endl; 
			return false;
		}
	}
	else{
		if(!current_client->chat_sym_key){
			cerr << "no session key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "no iv between client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}	


	memcpy(plaintext, &opcode, plain_size); 
	memcpy(aad, IV, nonce_length); 
	
	
	//criptaggio plaintext 
	int len;
	int ciphertext_len;
	
	//Crea e inizializza il contesto
	ctx = EVP_CIPHER_CTX_new();

	// Encrypt init
	EVP_EncryptInit(ctx, EVP_aes_128_gcm(), aes_key, IV);

	//inizializzazione aad
	EVP_EncryptUpdate(ctx, NULL, &len, aad, nonce_length);
	
	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_size);
	ciphertext_len = len;

	//Encrypt Final
	ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
	if(!ret){
		cerr << "Error Encrypt Final" << endl; 
		return false; 
	}
	ciphertext_len += len;
	  
	//Scrittura tag
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag); 
	EVP_CIPHER_CTX_free(ctx);

		if(ciphertext_len!=cipher_size){
		cerr << "Error" << endl; 
		return false; 
	}
	
	memcpy(total_message, aad, nonce_length); 
	memcpy(total_message + nonce_length, ciphertext, cipher_size);
	memcpy(total_message + nonce_length + cipher_size, tag, 16);  
	
	ret = send(socket, (void*)total_message, total_size, 0);
	if(ret <= 0 || ret != (int)total_size){ 
		cerr << "Error send" << endl;
		return false;
	}
	
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key);
	OPENSSL_free(plaintext);
	OPENSSL_free(ciphertext); 
	
	return true; 
}

//funzione che invia la lista dei nomi dei client online 
bool on_clients( int c_socket){
	
	uint32_t full_dim = 0;
	Clients* req=get_client(c_socket);
	Clients* curr=clients;
	char* list=NULL;

	while(curr!=NULL){

		if(curr->busy==0 && strcmp(curr->name,req->name)!=0){
			if(list==NULL){
				full_dim+=strlen(curr->name);
				list=(char*)malloc(full_dim*sizeof(char)+1);
				list=strncpy(list,curr->name,strlen(curr->name));
				list[full_dim]='_';
			}
			else{
				full_dim+=strlen(curr->name);
				list=(char*)realloc(list,full_dim*sizeof(char)+1);
				list=strncat(list,curr->name,full_dim);
				list[full_dim+1]='_';

			}
		}
		curr=curr->next;
	}
	if(list!=NULL)
		full_dim=strlen(list);
	
	//invio dimensione lista
	if(!sendCode(c_socket, full_dim, session_value)){
		cerr << "Error sending size" << endl; 
		return false; 
	}
	
	//termina la funzione in caso di nessun client online
	if(full_dim == 0)
		return true; 

	
	//invio lista utenti 
	if(!sendAutData(c_socket, (unsigned char*)list, full_dim,req)){
		cerr << "Error send list" << endl; 
		return false; 
	}

	return true; 
}

bool sendAutData(int socket, unsigned char* data, int data_size, Clients* current_client){
	
	int ret; 
	int session_type=0;
	//preparazione del messaggio da autenticare 
	uint32_t aad_size = data_size + nonce_length; 
	uint32_t total_size = aad_size + 16; 
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(aad_size);
	
	//Incremento numero di sequenza 
	inc_iv(session_value,current_client); 
	
	//generazione oggetto per la codifica
if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no session key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "no iv between client server" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client server" << endl; 
			return false;
		}
	}
	else{
		if(!current_client->chat_sym_key){
			cerr << "no session key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "no iv between client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}	

	memcpy(aad, IV, nonce_length); 
	memcpy(aad + nonce_length, data, data_size); 
	
	int len;
	//creazione tag per l'autenticazione 
	//Crea e inizializza il contesto
	ctx = EVP_CIPHER_CTX_new();

	// Encrypt init
	EVP_EncryptInit(ctx, EVP_aes_128_gcm(), aes_key, IV);

	//inizializzazione aad
	EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size);
	
	//Encrypt Final
	ret = EVP_EncryptFinal(ctx, NULL, &len);
	if(!ret){
		cerr << "Error Encrypt Final" << endl; 
		return false; 
	}
	  
	//Scrittura tag
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag); 
	  
	EVP_CIPHER_CTX_free(ctx);
	
	//inserimento nel buffer per l'invio dei dati che compongono il messaggio 
	memcpy(total_message, IV, nonce_length); 
	memcpy(total_message + nonce_length, data, data_size);
	memcpy(total_message + aad_size, tag, 16);
	 
	//invio 
	ret = send(socket, (void*)total_message, total_size, 0);
	if(ret <= 0 || ret != (int)total_size){ 
		cerr << "Error" << endl;
		return false;
	}
	
	
	OPENSSL_free(aad);
	OPENSSL_free(aes_key);
	
	return true; 
	
}

bool recvSecureData(int socket, unsigned char* data, uint32_t data_size, int session_type){
	
	int ret; 
	Clients* current_client=get_client(socket);
	//preparazione dei buffer per la ricezione del messaggio e 
	// per il decriptaggio 
	uint32_t plain_size = data_size; 
	uint32_t cipher_size = plain_size; 
	uint32_t total_size = nonce_length + cipher_size + 16;	
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
	unsigned char* plaintext = (unsigned char*)malloc(plain_size); 
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_size);
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(nonce_length);
	unsigned char* received_seq_number = (unsigned char*)malloc(nonce_length);
	
	
	//ricezione messaggio
	if(session_type == 1){
		if(!recvAutData(socket, total_message, total_size, session_value)){
			cerr << "Error recvSecureData" << endl; 
			return false; 
		}
	}
	else{
		ret = recv(socket, (void*) total_message, total_size, 0);
		if(ret <= 0 || ret != (int)total_size){ 
			cerr << "Error recv" << endl;
			return false;
		}
	}
	 
	//copio i valori nei buffer
	memcpy(aad, total_message, nonce_length); 
	memcpy(ciphertext, total_message + nonce_length, cipher_size);
	memcpy(tag, total_message + nonce_length + cipher_size, 16); 
	memcpy(received_seq_number, total_message, nonce_length); 

	//incremento il numero di sequenza e lo carico nel buffer per il confronto 
	inc_iv(session_type,current_client);
//generazione oggetto per la codifica

if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no session key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "no iv between client server" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client server" << endl; 
			return false;
		}
	}
	else{
		if(!current_client->chat_sym_key){
			cerr << "no session key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "no iv between client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}	
	
	//valuto se il numero di sequenza ricevuto è corretto
	if(memcmp(received_seq_number, IV, nonce_length)){
		cerr << "wrong sequence number received" << endl; 
		return false; 
	}
	
	//decriptaggio plaintext 
	int len; 
	int plaintext_len; 
	
	//inizializzazione contesto 
	ctx = EVP_CIPHER_CTX_new(); 
	
	EVP_DecryptInit(ctx, EVP_aes_128_gcm(), aes_key, IV);
	
	EVP_DecryptUpdate(ctx, NULL, &len, aad, nonce_length);
	
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_size);
	plaintext_len = len; 
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) ;

	ret = EVP_DecryptFinal(ctx, plaintext + len, &len);
	if(!ret){
		cerr << "Error Decrypt Final" << endl; 
		return false; 
	}
	plaintext_len += len; 

	EVP_CIPHER_CTX_free(ctx); 
		if(plaintext_len!=plain_size){
		cerr << "Error" << endl;
		return false; 
	}
	
	//copio lista nel buffer corretto  
	memcpy(data, plaintext, data_size); 
	
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key); 
	OPENSSL_free(plaintext);
	OPENSSL_free(ciphertext);
	
	return true;
}

bool recvAutData(int socket, unsigned char* data, int data_size, int session_type){
	
	int ret; 

	Clients* current_client=get_client(socket);

	//preparazione dei buffer per la ricezione del messaggio e 
	// per il decriptaggio 
	uint32_t aad_size = nonce_length + data_size;  
	uint32_t total_size = aad_size + 16;	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(aad_size);
	unsigned char* received_seq_number = (unsigned char*)malloc(nonce_length);
	
	//ricezione messaggio
	ret = recv(socket, (void*) total_message, total_size, 0);
	if(ret <= 0 || ret != (int)total_size){ 
		printf("%d %d %d\n",nonce_length, data_size, aad_size);

		cerr << "Error recv "<< ret << " " << total_size<< endl;
		return false;
	}

	 
	//copio i valori nei buffer
	memcpy(aad, total_message, aad_size);
	memcpy(tag, total_message + aad_size, 16); 
	memcpy(received_seq_number, total_message, nonce_length); 

	//incremento il numero di sequenza e lo carico nel buffer per il confronto 
	inc_iv(session_value,current_client);
	//generazione oggetto per la codifica

	if(session_type == session_value){
			if(!current_client->client_server_symmetric_key){
				cerr << "no session key client server" << endl; 
				return false; 
			} 
			memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
			if(!aes_key){
				cerr <<"error getting session key client server" << endl; 
				return false;
			}
			
			if(!current_client->IV){
				cerr << "no iv between client server" << endl; 
				return false; 
			} 
			memcpy(IV, current_client->IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
			if(!aes_key){
				cerr <<"error getting iv client server" << endl; 
				return false;
			}
		}
		else{
			if(!current_client->chat_sym_key){
				cerr << "no session key client client" << endl; 
				return false; 
			} 
			memcpy(aes_key, current_client->chat_sym_key, 16); 
			if(!aes_key){
				cerr <<"error getting session key client client" << endl; 
				return false;
			}
			
			if(!current_client->chat_IV){
				cerr << "no iv between client client" << endl; 
				return false; 
			} 
			memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
			if(!aes_key){
				cerr <<"error getting iv client client" << endl; 
				return false;
			}
			
		}	
	
	//valuto se il numero di sequenza ricevuto è corretto
	if(memcmp(received_seq_number, IV, nonce_length)){
		cerr << "wrong sequence number received" << endl; 
		return false; 
	}
	

	//decriptaggio plaintext 
	int len;  
	ret=true;
	//creazione nuovo contesto 
	ctx = EVP_CIPHER_CTX_new(); 
	
	//inizializzazione contesto 
	EVP_DecryptInit(ctx, EVP_aes_128_gcm(), aes_key, IV);
	
	EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) ;

	ret = EVP_DecryptFinal(ctx, NULL, &len);
	if(!ret){
		cerr << "Error Decrypt Final" << endl; 
		return false; 
	}

	EVP_CIPHER_CTX_free(ctx); 	
	if(ret!=true){
		cerr << "Error" << endl;
		return false; 
	}
	
	//copio lista nel buffer corretto  
	memcpy(data, total_message + nonce_length, data_size); 
	
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key); 
	OPENSSL_free(aad); 
	
	return true;
}

bool sendSecureData(int socket, unsigned char* data, uint32_t data_size, int session_type){
	
	int ret; 
	Clients* current_client=get_client(socket);
	//preparazione del messaggio da criptare 
	uint32_t plain_size = data_size; 
	uint32_t cipher_size = plain_size; 
	uint32_t total_size = nonce_length + cipher_size + 16; 
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
	unsigned char* plaintext = (unsigned char*)malloc(plain_size); 
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_size);
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(nonce_length);
	
	//Incremento numero di sequenza 
	inc_iv(session_type,current_client);
	//generazione oggetto per la codifica
	//generazione oggetto per la codifica

	if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no session key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "no iv between client server" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client server" << endl; 
			return false;
		}
	}
	else{
		if(!current_client->chat_sym_key){
			cerr << "no session key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting session key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "no iv between client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}	

	memcpy(plaintext, data, plain_size); 
	memcpy(aad, IV, nonce_length); 
	
	
	//criptaggio plaintext 
	int len;
	int ciphertext_len;
	
	//Crea e inizializza il contesto
	ctx = EVP_CIPHER_CTX_new();

	// Encrypt init
	EVP_EncryptInit(ctx, EVP_aes_128_gcm(), aes_key, IV);

	//inizializzazione aad
	EVP_EncryptUpdate(ctx, NULL, &len, aad, nonce_length);
	
	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_size);
	ciphertext_len = len;

	//Encrypt Final
	ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
	if(!ret){
		cerr << "Error Encrypt Final" << endl; 
		return false; 
	}
	ciphertext_len += len;
	  
	//Scrittura tag
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag); 
	  
	EVP_CIPHER_CTX_free(ctx);	
	if(ciphertext_len!=cipher_size){
		cerr << "Error" << endl; 
		return false; 
	}
	
	memcpy(total_message, aad, nonce_length); 
	memcpy(total_message + nonce_length, ciphertext, cipher_size);
	memcpy(total_message + nonce_length + cipher_size, tag, 16);  
	
	if(session_type == 1){
		if(!sendAutData(socket, total_message, total_size,current_client)){
			cerr << "Error sendAutData" << endl; 
			return false; 
		}
	}
	else{
		ret = send(socket, (void*)total_message, total_size, 0);
		if(ret <= 0 || ret != (int)total_size){ 
		cerr << "Error send" << endl;
		return false;
		}
	}
	
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key);
	OPENSSL_free(plaintext);
	OPENSSL_free(ciphertext); 
	
	return true; 
}

bool StartChat(int c1_socket, int* c2_socket, int* esito){
	
	Clients* current_client=get_client(c1_socket);
	//ricezione nome client 
	unsigned char* c2_name = (unsigned char*)malloc(length_max_users);
	unsigned char* check = (unsigned char*)malloc(length_max_users);
	uint32_t c2_name_size = length_max_users; 
	if(!recvSecureData(c1_socket, c2_name, c2_name_size, session_value)){
		cerr << "Error recvSecureData" << endl; 
		return false; 
	}
	
	//controllo validità nome ricevuto 
	check=(unsigned char*)strcpy((char*)check,(char*)current_client->name); 
	if(strncmp((char*)check, (char*)c2_name, strlen((char*)check)) == 0){
		cout << "Error: chat request to myself" << endl; 
		return false; 
	}
	
	
	//reperimento socket del Client2 e puntatore al Client2
	*c2_socket = get_socket((char*)c2_name); 
	Clients* client2=get_client(*c2_socket);
	if(client2==NULL){
		cerr << "Client " << c2_name << " offline" << endl; 
		
		//invio dell'esito negativo al Client1 
		if(!sendCode(c1_socket, 5, session_value)){
			cerr << "Error sendCode" << endl; 
			return false; 
		}
		
		return false; 
	}
	
	//controllo che il Client2 non sia già occupato 
	if(!client2->busy){
	
		//invio messaggio di richiesta chat al Client2 
		if(!sendCode(*c2_socket, 9, session_value)){
			cerr << "Error sendCode" << endl; 
			return false; 
		}
		
		//invio nome del Client1 che vuole chattare 
		unsigned char* c1_name = (unsigned char*)malloc(length_max_users); 
		c1_name=(unsigned char*)strcpy((char*)c1_name,(char*)current_client->name);
		if(!sendSecureData(*c2_socket, c1_name, length_max_users, session_value)){
			cerr << "Error sendSecureData" << endl; 
			return false; 
		}
		
		//ricezione esito della richiesta di chat dal Client2
		uint32_t esito_richiesta = 0; 
		if(!recvCode(*c2_socket, &esito_richiesta, session_value)){
			cerr << "Error recvCode" << endl; 
			return false;
		}
		
		//invio dell'esito al Client1 
		if(!sendCode(c1_socket, esito_richiesta, session_value)){
			cerr << "Error sendCode" << endl; 
			return false; 
		}
		
		if(esito_richiesta == 7){
			change_state(current_client,1);
			change_state(client2,1);
			current_client->socket_dest=*c2_socket;
			client2->socket_dest=c1_socket;
			*esito = 7; 
		}
		else{
			*esito = 5; 
			return true; 
		}
		
		//reperimento chiavi pubbliche client per invio 
		//Client 1
		EVP_PKEY* c1_pubkey = NULL; 
		string c1_key_file_name = "./server/database/users/";
		c1_key_file_name.append((char*)c1_name); 
		c1_key_file_name.append("_public.pem"); 
		FILE* c1_key_file = fopen(c1_key_file_name.c_str(), "r"); 
		if(!c1_key_file){
			cerr << "Error opening the private key" << endl; 
			return false; 
		}
		c1_pubkey = PEM_read_PUBKEY(c1_key_file, NULL, NULL, NULL); 
		if(!c1_pubkey){
			cerr <<"Error opening the private key"<<endl; 
			return false; 
		}
		fclose(c1_key_file); 
		
		//Client2
		EVP_PKEY* c2_pubkey = NULL; 
		string c2_key_file_name = "./server/database/users/";
		c2_key_file_name.append((char*)c2_name); 
		c2_key_file_name.append("_public.pem"); 
		FILE* c2_key_file = fopen(c2_key_file_name.c_str(), "r"); 
		if(!c2_key_file){
			cerr << "Error opening the private key" << endl; 
			return false; 
		}
		c2_pubkey = PEM_read_PUBKEY(c2_key_file, NULL, NULL, NULL); 
		if(!c2_pubkey){
			cerr <<"Error opening the private key"<<endl; 
			return false; 
		}
		fclose(c2_key_file); 
		
		//serializzazione chiave pubblica Client 1 
		BIO* c1_pub_bio = BIO_new(BIO_s_mem()); 
		PEM_write_bio_PUBKEY(c1_pub_bio, c1_pubkey); 
		char* c1_pubkey_buf = NULL; 
		long c1_pubkey_buf_size = BIO_get_mem_data(c1_pub_bio, &c1_pubkey_buf); 
		unsigned char* c1_pubkey_sentbuf = (unsigned char*)malloc(c1_pubkey_buf_size); 
		memcpy(c1_pubkey_sentbuf, c1_pubkey_buf, c1_pubkey_buf_size); 
		
		
		//serializzazione chiave pubblica Client2 
		BIO* c2_pub_bio = BIO_new(BIO_s_mem()); 
		PEM_write_bio_PUBKEY(c2_pub_bio, c2_pubkey); 
		char* c2_pubkey_buf = NULL; 
		long c2_pubkey_buf_size = BIO_get_mem_data(c2_pub_bio, &c2_pubkey_buf);
		unsigned char* c2_pubkey_sentbuf = (unsigned char*)malloc(c2_pubkey_buf_size); 
		memcpy(c2_pubkey_sentbuf, c2_pubkey_buf, c2_pubkey_buf_size);
	
		
		//invio chiave pubblica Client2 al Client 1 
		if(!sendAutData(c1_socket, c2_pubkey_sentbuf, c2_pubkey_buf_size,current_client)){
			cerr << "Error sendautdata" << endl; 
			return false; 
		}
		
		//invio chiave pubblica Client1 al Client2 
		if(!sendAutData(*c2_socket,c1_pubkey_sentbuf, c1_pubkey_buf_size,client2)){
			cerr << "Error sendautdata" << endl; 
			return false; 
		}
		
		return true; 
	}
		
	*esito = 5; 
	
	//invio dell'esito negativo al Client1 
	if(!sendCode(c1_socket, 5, session_value)){
		cerr << "Error sendCode" << endl; 
		return false; 
	}
	
	return true; 
}

bool ClientHandshake(int c1_socket, int c2_socket){
	
	Clients* client1=get_client(c1_socket);
	Clients* client2=get_client(c2_socket);

	//ricezione messaggio autenticato dal Client1 formato così: 
	// (n.s.s || R || TAG)	
	uint32_t R_size = nonce_length; 
	unsigned char* R = (unsigned char*)malloc(R_size); 
	
	if(!recvAutData(c1_socket, R, R_size, session_value)){
		cerr << "Error recvAutData" << endl; 
		return false; 
	}
	
	//inoltro messaggio autenticato al Client2 
	if(!sendAutData(c2_socket, R, R_size, client2)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}
	
	//ricezione messaggio autenticato dal Client2 formato così: 
	// (n.s.s || Tpubkey || DS(R || Tpubkey) || TAG)
	uint32_t message_size = 451 + 384;
	unsigned char* message = (unsigned char*)malloc(message_size); 
	
	if(!recvAutData(c2_socket, message, message_size, session_value)){
		cerr << "Error recvAutData" << endl; 
		return false; 
	}
	
	//inoltro messaggio auntenticato al Client1 
	if(!sendAutData(c1_socket, message, message_size, client1)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}
	
	//ricezione messaggio auntenticato dal Client1 formato così: 
	// (n.s.s || IV || E(Tpubkey, k) || E(k, aes_key) || DS(Tpubkey || E(Tpubkey, k)) || TAG) 
	uint32_t final_message_size = nonce_length + 256 + 16 + 384; 
	unsigned char* final_message = (unsigned char*)malloc(final_message_size); 
	
	if(!recvAutData(c1_socket, final_message, final_message_size, session_value)){
		cerr << "Error recvAutData" << endl; 
		return false; 
	}
	
	//inoltro messaggio autenticato al Client2
	if(!sendAutData(c2_socket, final_message, final_message_size,client2)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}
	
	
	cout << "session established between: " << client1->name << " and " << client2->name << endl << endl; 
	
	return true; 	
}

bool ExchangeMessage(int c1_socket){
	
	int ret; 
	Clients* client1=get_client(c1_socket);
	int c2_socket = client1->socket_dest; 
	Clients* client2=get_client(c2_socket);

	
	//informo il Client2 che sta per arrivare un messaggio
	if(!sendCode(c2_socket, 6, session_value)){
		cerr << "Error sendCode" << endl; 
		return false; 
	}
	
	//ricezione dimensione messaggio da recapitare al Client2
	unsigned char* size = (unsigned char*)malloc(sizeof(uint32_t));
	
	if(!recvAutData(c1_socket, size, sizeof(uint32_t), session_value)){
		cerr << "Error recvAutData" << endl; 
		return false; 
	}
	

	uint32_t message_size = nonce_length + (uint32_t)*size + 16; 

	unsigned char* message = (unsigned char*)malloc(message_size); 
	
	 //ricezione messaggio 
	if(!recvAutData(c1_socket, message, message_size, session_value)){
		cerr << "Error recvAutData" << endl; 
		return false; 
	}
	
	
	//inoltro dimensione messaggio al Client2 
	if(!sendAutData(c2_socket,  size, sizeof(uint32_t), client2)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}
	
	//inoltro messaggio al Client2 
	if(!sendAutData(c2_socket, message, message_size, client2)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}
	
	return true; 
}