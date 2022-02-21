#include<iostream>
#include<crypto_client.hpp>
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
#include <iomanip>     
 #include <openssl/err.h>
using namespace std;



bool create_nonce(unsigned char* nonce);
bool transmit_data(int socket, unsigned char *data, uint32_t data_length);
bool rcv_uint(int socket, uint32_t &num);
bool receive_data(int socket, unsigned char *&data, uint32_t data_length);
int envelope_encrypt(unsigned char *plaintext, int plaintext_len, EVP_PKEY* pubkey, unsigned char *iv, unsigned char *ciphertext, unsigned char* en_key, int en_key_len);
int envelope_decrypt(unsigned char *ciphertext, int cipher_len, EVP_PKEY* privkey, unsigned char *iv, unsigned char *plaintext, unsigned char* en_key, int en_key_size);
bool save_key(unsigned char* symmetric_key, unsigned char* iv, int session_type, Clients* current_client);
int quit_from_the_server();
void increment(unsigned char* buffer, uint32_t size);
void inc_iv(int session_type);
int startchat();
bool sendSecureData(int socket, unsigned char* data, uint32_t data_size, int sessione);
bool sendAutData(int socket,  unsigned char* data, int data_size);
bool recvAutData(int socket, unsigned char* data, int data_size, int sessione);
bool recvCode(int socket, uint32_t* received_opcode, int sessione);
int handshake_caller();
bool next_operation_for_server(int, uint32_t, int);
int am_i_chatting();
void change_state(int n);
bool chat_request();
bool recvSecureData(int socket, unsigned char* data, uint32_t data_size, int sessione);
bool handshake_called();
int create_temp_rsa_key(EVP_PKEY *newSK);
bool recvMessage();
bool sendMessage(char* read_message, uint32_t message_size);
bool receive_for_next_operation_server(int socket_c,uint32_t*  rec_opcode,int session_type);
bool show_online_clients();

Clients* current_client;
int socket_c;
int session_type=0; //modalità corrente del client, all'inizio vale 0
EVP_PKEY* chatter_pubkey = NULL; 

EVP_CIPHER_CTX* ctx; 


int login_client(int socket, char* client_name){
socket_c=socket;
current_client=(Clients*)malloc(sizeof(Clients));

//variabile per controllo ritorno 
	int ret; 
	
	//buffer per la ricezione dei messaggi e dimensioni 
	unsigned char* c_clear_message, *s_clear_message;
	unsigned char* c_total_message, *s_total_message; 
	unsigned char* s_signed_message; 
	unsigned char* server_sign;
	unsigned char* client_sign; 
	unsigned char* server_cert;	
	unsigned char* client_nonce;
	unsigned char* server_nonce; 
	unsigned char* temp_nonce; 
	
	uint32_t clear_message_size; 
	uint32_t total_message_size; 
	uint32_t signed_message_size;
	uint32_t server_sign_size; 
	uint32_t client_sign_size;
	uint32_t server_cert_size; 
	uint32_t serialized_Tpubkey_size; 
		
	
	serialized_Tpubkey_size = 451;  
	server_sign_size = 256;
	client_nonce = (unsigned char*)malloc(nonce_length);
	server_nonce = (unsigned char*)malloc(nonce_length);
	temp_nonce = (unsigned char*)malloc(nonce_length);

//invio messaggio M1 al server per l'autenticazione

	//creazione nonce
	create_nonce(client_nonce);  						
	
	//creazione messaggio 
	clear_message_size = nonce_length + length_max_users; 
	total_message_size = clear_message_size;
	
	c_clear_message = (unsigned char*)malloc(clear_message_size); 
	c_total_message = (unsigned char*)malloc(total_message_size);
	
	memcpy(c_clear_message, client_nonce, nonce_length); 
	memcpy(c_clear_message + nonce_length, client_name, length_max_users); 
	memcpy(c_total_message, c_clear_message, clear_message_size); 

	//invio messaggio
	if(!transmit_data(socket, c_total_message, total_message_size)){
			cerr << "Error transmitting the auth message" <<endl; 
			return -1; 	
	} 
	OPENSSL_free(c_total_message);
	OPENSSL_free(c_clear_message); 

//creazione store per verifica certificato server 

	//lettura certificato CA e crl 
	X509* CA_cert; 
	X509_CRL* CA_crl; 
	

	FILE* CA_cert_file = fopen("./client/CA/CA_cert.pem", "r"); 
	if(CA_cert_file==NULL){
		printf("NULL EXITING");
		exit(1);
	}

	CA_cert = PEM_read_X509(CA_cert_file, NULL, NULL, NULL); 
	if(!CA_cert){ cerr<<"Error while opening cert file" << endl;  exit(1); }
	fclose(CA_cert_file); 
	
	FILE* CA_crl_file = fopen("./client/CA/CA_cert_crl.pem", "r"); 
	CA_crl = PEM_read_X509_CRL(CA_crl_file, NULL, NULL, NULL); 
	if(!CA_crl){ cerr<<"error while opening crl" << endl;  exit(1); }
	fclose(CA_crl_file); 
	
	//costruzione store e aggiunta certificato CA e crl
	X509_STORE* store = X509_STORE_new(); 
	ret = X509_STORE_add_cert(store, CA_cert); 
	if(ret!=1){cerr<<"Error adding the certificate"<<endl; exit(1);}
	ret= X509_STORE_add_crl(store, CA_crl); 
	if(ret!=1){cerr<<"Error adding the CRL"<<endl; exit(1);}
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK); 

//preparazione e ricezione di M2
	//ricezione da socket della dimensione del certificato 
	if(!rcv_uint(socket, server_cert_size)){
		 cerr << "Error receiving the size" << endl;
		 return -1; 
	}

	if(server_cert_size==-1){
		printf("Error: User already logged to the server\n");
		return -1;
	}
	server_cert = (unsigned char*)malloc(server_cert_size); 
	 
	//strutture per la chiave pubblica long term e quella temporanea 
	EVP_PKEY* server_pubkey = NULL; 
	EVP_PKEY* Tpubkey = EVP_PKEY_new(); 
	BIO *Tpubkeybio = BIO_new(BIO_s_mem()); 
	unsigned char* serialized_Tpubkey; 
	
	//creazione buffer per la ricezione del messaggio per intero e per i vari campi
	clear_message_size = nonce_length + server_cert_size + serialized_Tpubkey_size;  
	signed_message_size = serialized_Tpubkey_size + nonce_length; 
	total_message_size = clear_message_size + server_sign_size; 
	 
	s_total_message = (unsigned char*)malloc(total_message_size); 
	s_clear_message = (unsigned char*)malloc(clear_message_size);
	s_signed_message = (unsigned char*)malloc(signed_message_size); 
	server_sign = (unsigned char*)malloc(server_sign_size); 
	serialized_Tpubkey = (unsigned char*)malloc(serialized_Tpubkey_size);
	
	//ricezione messaggio
	if(!receive_data(socket, s_total_message, total_message_size)){
		cerr << "Error receiving the message" <<endl; 
		return -1; 
	}
	 
	//immissione valori nei buffer
	memcpy(s_clear_message, s_total_message, clear_message_size);  
	memcpy(server_nonce, s_total_message, nonce_length); 
	memcpy(serialized_Tpubkey, s_total_message + nonce_length,serialized_Tpubkey_size); 
	memcpy(server_cert, s_total_message + nonce_length + serialized_Tpubkey_size, server_cert_size); 
	memcpy(server_sign, s_total_message + clear_message_size, server_sign_size); 
	 


	//creazione messaggio firmato per la verifica
	memcpy(s_signed_message, serialized_Tpubkey, serialized_Tpubkey_size); 
	memcpy(s_signed_message + serialized_Tpubkey_size, client_nonce, nonce_length); 
	  
	 //deserializzazione certificato 
	X509* s_cert; 
	s_cert = d2i_X509(NULL, (const unsigned char**)&server_cert, server_cert_size); 
	if(!s_cert){
		cerr<<"Errore deserializing the certificate"<<endl; 
		return -1; 
	}	 
	

//verifica certificato e firma digitale del server 
	
	//creazione contesto e verifica certificato
	X509_STORE_CTX *ctx_verifica = X509_STORE_CTX_new(); 
	X509_STORE_CTX_init(ctx_verifica, store, s_cert, NULL); 
	ret = X509_verify_cert(ctx_verifica); 

	if(ret != 1){
		cerr<<"Error verifying the certificate" << endl; 
		X509_STORE_CTX_free(ctx_verifica); 
		return -1; 
	}
	X509_STORE_CTX_free(ctx_verifica); 
	server_pubkey = X509_get_pubkey(s_cert); 
	server_sign_size = EVP_PKEY_size(server_pubkey); 
	
	//verifica firma 
	EVP_MD_CTX* server_sign_ctx = EVP_MD_CTX_new(); 
	EVP_VerifyInit(server_sign_ctx, EVP_sha256());
	EVP_VerifyUpdate(server_sign_ctx, s_signed_message, signed_message_size);
	ret = EVP_VerifyFinal(server_sign_ctx, server_sign, server_sign_size, server_pubkey);
	if(ret != 1){
		cerr << "Error verifying the signature" << endl; 
		EVP_MD_CTX_free(server_sign_ctx); 
		return -1; 
	}
	EVP_MD_CTX_free(server_sign_ctx); 
	
	//estrazione chiave pubblica temporanea
	ret = BIO_write(Tpubkeybio, serialized_Tpubkey, serialized_Tpubkey_size ); 
	if(!ret){
		cerr << "Error writing the pub key - BIO" << endl; 
		return -1; 
	}
	Tpubkey = PEM_read_bio_PUBKEY(Tpubkeybio, NULL, NULL, NULL); 
	
	OPENSSL_free(s_total_message); 
	OPENSSL_free(s_clear_message); 
	OPENSSL_free(server_sign); 


//Creazione messaggio da inviare (s_nonce || IV || E_Tpubkey(key) || E_Tpubkey(aes_gcm_key) || DS)

	//creazione chiave simmetrica e criptaggio con chiave pubblica temporanea
	uint32_t IV_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());		
	uint32_t en_key_size = EVP_PKEY_size(Tpubkey);
	
	unsigned char* aes_key = (unsigned char*)malloc(aes_key_length);
	unsigned char*crypted_aes_key = (unsigned char*)malloc(aes_key_length); 
	unsigned char* IV = (unsigned char *)malloc(IV_size);
	unsigned char* en_key = (unsigned char*)malloc(en_key_size); 

	RAND_poll(); 
	RAND_bytes(aes_key, aes_key_length); 
	RAND_bytes(IV, IV_size);
	
	uint32_t envelope_size = envelope_encrypt( aes_key, aes_key_length , Tpubkey, IV, crypted_aes_key, en_key, en_key_size); 
	
	//lettura chiave privata client
	EVP_PKEY* client_privkey = NULL; 
	string client_key_file_name = "./client/database/";
	client_key_file_name.append((char*)client_name); 
	client_key_file_name.append("_private.pem"); 
	FILE* client_key_file = fopen(client_key_file_name.c_str(), "r"); 
	if(!client_key_file){
		cerr << "Error while opening the private key" << endl; 
		return -1; 
	}
	client_privkey = PEM_read_PrivateKey(client_key_file, NULL, NULL, NULL); 
	if(!client_privkey){
		cerr <<"Error while opening the private key"<<endl; 
		return -1; 
	}
	fclose(client_key_file); 

    //dimensionamento buffer per creazione
	clear_message_size = nonce_length+ en_key_size + IV_size + envelope_size;
	c_clear_message = (unsigned char*)malloc(clear_message_size); 
	client_sign_size = EVP_PKEY_size(client_privkey); 
	client_sign = (unsigned char*)malloc(client_sign_size); 

	memcpy(c_clear_message, server_nonce, nonce_length); 
	memcpy(c_clear_message + nonce_length, IV, IV_size); 
	memcpy(c_clear_message + nonce_length + IV_size, en_key, en_key_size);	
	memcpy(c_clear_message + nonce_length + IV_size + en_key_size, crypted_aes_key, envelope_size);
		
	//firma
	EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new(); 
	EVP_SignInit(sign_ctx, EVP_sha256());
	EVP_SignUpdate(sign_ctx, c_clear_message, clear_message_size);
	EVP_SignFinal(sign_ctx, client_sign, &client_sign_size, client_privkey);  
	EVP_MD_CTX_free(sign_ctx); 
	EVP_PKEY_free(client_privkey); 

    //creazione messaggio definitivo 
	total_message_size = clear_message_size + client_sign_size; 
	c_total_message = (unsigned char*)malloc(total_message_size); 
	
	memcpy(c_total_message, c_clear_message, clear_message_size); 
	memcpy(c_total_message + clear_message_size, client_sign, client_sign_size); 
	
	//invio
	if(!transmit_data(socket, c_total_message, total_message_size)){
		cerr << "Error sending the authentication message" <<endl; 
		return -1; 	
	} 

    //salvataggio nel client della chiave e del IV per la comunicazione con il server
    if(!save_key(aes_key,IV,session_type,current_client)) cerr<<"Error while saving the key and vector"<<endl;
	current_client->name=client_name;

    //pulizia
	OPENSSL_free(c_total_message); 
	OPENSSL_free(c_clear_message); 
	OPENSSL_free(client_sign);
	OPENSSL_free(aes_key); 
	

return 0;
}


//funzione per ottenere un nuovo nonce random 
bool create_nonce(unsigned char* nonce){

	RAND_poll();
	int ret = RAND_bytes(nonce, nonce_length); 
	if(!ret){
		cerr << "Error generating the new nonce" << endl; 
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

//funzione per la ricezione di uint32_t, usata nella ricezione della dimensione del certificato e 
//nella ricezione del nonce 
bool rcv_uint(int socket, uint32_t &num){
	
	int ret; 
	uint32_t num_r;
	
	ret = recv(socket, (void*) &num_r, sizeof(num_r), 0); 
	if(ret < 0 || ret != sizeof(num_r)){
		cerr << "Error receiving the uint32_t" << endl; 
		return false; 
	}
	
	num = ntohl(num_r); //da network order a host order 
	
	return true; 
}

bool receive_data(int socket, unsigned char *&data, uint32_t data_length){
	
	if(recv(socket, (void*) data, data_length, 0) <= 0 || recv(socket, (void*) data, data_length, 0) != (int)data_length){ 
		cerr << "Error receiving data in recvData" << endl;
		return false;
	}

	return true;
}

int envelope_encrypt(unsigned char *plaintext, int plaintext_len, EVP_PKEY* pubkey,
  unsigned char *iv, unsigned char *ciphertext, unsigned char* en_key, int en_key_len){
	  
	  int len;
	  int ciphertext_len, ret;
	  EVP_CIPHER_CTX* ctx; 

	  /* Create and initialise the context */
	  ctx = EVP_CIPHER_CTX_new();
	  
	  // SealInit
	  ret = EVP_SealInit(ctx, EVP_aes_128_gcm(), &en_key, &en_key_len, iv, &pubkey, 1);
	  if(!ret){
		 cout << "error in the SealInit" << endl; 
		 return 0; 
	  }
	  
	  EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	  ciphertext_len = len;

	  //Encrypt Final. Finalize the encryption and adds the padding
	  EVP_SealFinal(ctx, ciphertext + len, &len);
	  ciphertext_len += len;

	  // MUST ALWAYS BE CALLED!!!!!!!!!!
	  EVP_CIPHER_CTX_free(ctx);

	  return ciphertext_len;
}

bool save_key(unsigned char* symmetric_key, unsigned char* iv, int session_type, Clients* current_client){
	if(session_type==0){
		if(current_client->client_server_symmetric_key==NULL)
			current_client->client_server_symmetric_key=(unsigned char*)malloc(aes_key_length); 
		memcpy(current_client->client_server_symmetric_key, symmetric_key, aes_key_length); 

		if(current_client->client_server_symmetric_key==NULL){
			cerr<<"Error saving the client server symmetric key";
			return false;
		}
		if(current_client->IV==NULL)
			current_client->IV=(unsigned char*) malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
		memcpy(current_client->IV, iv, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(current_client->IV==NULL){
			cerr<<"Error saving the iv between client and server";
			return false;
		}
	}
	else{
		if(current_client->chat_sym_key==NULL)
			current_client->chat_sym_key = (unsigned char*)malloc(16); 
		memcpy(current_client->chat_sym_key, symmetric_key, 16); 
		if(current_client->chat_sym_key==NULL){
			cerr <<"Error saving the session key client client" << endl; 
			return false;
		}
		
		if(current_client->chat_IV==NULL)
			current_client->chat_IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
		memcpy(current_client->chat_IV, iv, EVP_CIPHER_iv_length(EVP_aes_128_gcm() )); 
		if(current_client->chat_IV==NULL){
			cerr <<"Errore saving iv client client" << endl; 
			return false;
		}
	}
	return true;
}

int quit_from_the_server(){
	if(!next_operation_for_server(socket_c, 3, session_type)){
		cerr<<"error next op for server";
		return -1;
	}
	return 0;
}

bool next_operation_for_server(int socket, uint32_t code, int session_type){
	int ret; 
	
	//preparazione del messaggio da criptare 
	uint32_t plain_size = sizeof(uint32_t); 
	uint32_t cipher_size = plain_size; 
	uint32_t total_size = nonce_length + cipher_size + 16; //16 byte tag
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm() ));
	unsigned char* plaintext = (unsigned char*)malloc(plain_size); 
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_size);
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(nonce_length);
	
	//Incremento numero di sequenza 
	//funzione per l'incremento del numero di sequenza o dell'IV (se cond = 0 incremento seq. number altrimenti l'IV)
	inc_iv(session_type);
	

	//generazione oggetto per la codifica
if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}	
	
	//
	memcpy(plaintext, &code, plain_size); 
	memcpy(aad, IV, nonce_length); 
	
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
		cerr << "Error sending data" << endl;
		return false;
	}
	
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key);
	OPENSSL_free(plaintext);
	OPENSSL_free(ciphertext); 
	
	return true; 
}

//funzione per incrementare un buffer binario 
void increment(unsigned char* buffer, uint32_t size){

		uint32_t index = size - 1;
		
		buffer[index]++; 
		
		if(!buffer[index] && index){
			increment(buffer, index); 
		}
}

void inc_iv(int session_type){
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

int startchat(){
	int ret; 
	
	//invio al server dell OPCODE CHAT
	if(!next_operation_for_server(socket_c, 1, session_type)){
		cerr << "Error next operation for server" << endl; 
		return false; 
	}
	
	//lettura del nome del client con il quale si desidera parlare 
	unsigned char* other_client = (unsigned char*)malloc(length_max_users); 
	unsigned char* check = (unsigned char*)malloc(length_max_users); 
	memset(check, 0, length_max_users);
	memset(other_client, 0, length_max_users); 
	cout << "Insert the client name to start the chat: "; 
	cin >> other_client;
	
		//check del nome
	check=(unsigned char*)current_client->name;


		if(strncmp((const char*)check, (const char*)other_client, strlen((const char *)check)) == 0){
		cout << "You can't speak with yourself!" << endl;
		return -1; 
	}
	
	
	//invio nome del client al server 
	uint32_t other_client_size = length_max_users;
	if(!sendSecureData(socket_c, other_client, other_client_size, session_value)){
		cerr << "Error sendSecureData" << endl; 
		return -1; 
	}
	



	
	cout << endl << "sent chat request to: " << other_client << endl; 
		
	//attesa esito della risposta 
	uint32_t received_opcode = 0; 
	if(!recvCode(socket_c, &received_opcode, session_value)){
		cerr << "Error in recvCode" << endl; 
		return -1; 
	}
	
	if(received_opcode == 7){
	
		
		//ricezione chiave pubblica dell'altro client e deserializzazione
		int serialized_pubkey_size = 625; 
		unsigned char* serialized_pubkey = (unsigned char*)malloc(serialized_pubkey_size);		
		if(!recvAutData(socket_c, serialized_pubkey, serialized_pubkey_size, session_value)){
			cerr << "Error in recvAutData" << endl;
			return -1;
		}
		
		chatter_pubkey = NULL; 
		BIO *chatter_pubkeybio = BIO_new(BIO_s_mem());
		ret = BIO_write(chatter_pubkeybio, serialized_pubkey, serialized_pubkey_size ); 
		if(!ret){
			cerr << "Error write pub key BIO" << endl; 
			return -1; 
		}
		chatter_pubkey = PEM_read_bio_PUBKEY(chatter_pubkeybio, NULL, NULL, NULL);
	
		
		cout << "successfull pub key received" << endl;
	}
	else {
		cout << "chat request denied: client offline or busy or unregistered" << endl << endl; 
		return -1;
	}
	
	return 0; 
}

bool sendSecureData(int socket, unsigned char* data, uint32_t data_size, int session_type){
	
	int ret; 
	
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
	inc_iv(session_type); 
	
	//generazione oggetto per la codifica

if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
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
		cerr << "Error in Encrypt Final" << endl; 
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
		if(!sendAutData(socket, total_message, total_size)){
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

bool sendAutData(int socket, unsigned char* data, int data_size){
	
	int ret; 
	
	//preparazione del messaggio da autenticare 
	uint32_t aad_size = data_size + nonce_length; 
	uint32_t total_size = aad_size + 16; 
	
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
	unsigned char* tag = (unsigned char*)malloc(16); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(aad_size);
	
	//Incremento numero di sequenza 
	inc_iv(session_value); 
	
	//generazione oggetto per la codifica
if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
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
		cerr << "Error send" << endl;
		return false;
	}
	
	
	OPENSSL_free(aad);
	OPENSSL_free(aes_key);
	
	return true; 
	
}

bool recvAutData(int socket, unsigned char* data, int data_size, int session_type){
	
	int ret; 
	
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
		cerr << "Error recv" << endl;
		return false;
	}

	
	 
	//copio i valori nei buffer
	memcpy(aad, total_message, aad_size);
	memcpy(tag, total_message + aad_size, 16); 
	memcpy(received_seq_number, total_message, nonce_length); 

	//incremento il numero di sequenza e lo carico nel buffer per il confronto 
	inc_iv(session_value);
	//generazione oggetto per la codifica
if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
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
		cerr << "wrong sequence number received - error" << endl; 
		return false; 
	}
	
	
	//decriptaggio plaintext 
	int len;  
	
	//creazione nuovo contesto 
	ctx = EVP_CIPHER_CTX_new(); 
	
	//inizializzazione contesto 
	EVP_DecryptInit(ctx, EVP_aes_128_gcm(), aes_key, IV);
	
	EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) ;

	ret = EVP_DecryptFinal(ctx, NULL, &len);
	if(!ret){
		cerr << "Errore nella Decrypt Final" << endl; 
		return false; 
	}

	EVP_CIPHER_CTX_free(ctx); 
	
	//copio lista nel buffer corretto  
	memcpy(data, total_message + nonce_length, data_size); 
	
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key); 
	OPENSSL_free(aad); 
	
	return true;
}

//riceve e gestisce il messaggio (seq_number || E(aes_key, opcode) || TAG)
bool recvCode(int socket, uint32_t* received_opcode, int sessione){
	
	int ret; 
	
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
		cerr << "Error recv" << endl;
		return false;
	}
	

	 
	//copio i valori nei buffer
	memcpy(aad, total_message, nonce_length); 
	memcpy(ciphertext, total_message + nonce_length, cipher_size);
	memcpy(tag, total_message + nonce_length + cipher_size, 16); 
	memcpy(received_seq_number, total_message, nonce_length); 
	
	//incremento IV e lo carico per controllare il numero ricevuto 
	inc_iv(sessione);
//generazione oggetto per la codifica
if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
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
		cerr << "Error Decrypt Final" << endl; 
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

int handshake_caller(){
		
	int ret; 

	//creazione messaggio da inviare e invio 
	//(n.s.s || R || TAG)
	uint32_t R_size = nonce_length; 
	unsigned char* R = (unsigned char*)malloc(R_size); 
	create_nonce(R); 
	
	if(!sendAutData(socket_c, R, R_size)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}
		
	//creazione e allocazione buffer per ricezione messaggio 
	// (n.s.s || Tpubkey || DS(Tpubkey || R) || TAG)
	uint32_t serialized_Tpubkey_size = 451; 
	uint32_t c2_sign_size = 384; 
	uint32_t c2_signed_message_size = serialized_Tpubkey_size + R_size;
	uint32_t c2_total_size = serialized_Tpubkey_size + c2_sign_size; 

	unsigned char* c2_sign = (unsigned char*)malloc(c2_sign_size); 
	unsigned char* c2_signed_message = (unsigned char*)malloc(c2_signed_message_size); 
	unsigned char* c2_total_message = (unsigned char*)malloc(c2_total_size); 
	
	//creazione struttura per chiave pubblica temporanea Tpubkey
	EVP_PKEY* Tpubkey = EVP_PKEY_new(); 
	BIO *Tpubkeybio = BIO_new(BIO_s_mem()); 
	unsigned char* serialized_Tpubkey = (unsigned char*)malloc(serialized_Tpubkey_size);
	
	//ricezione messaggio autenticato 
	if(!recvAutData(socket_c, c2_total_message, c2_total_size, session_value)){
		cerr << "Error  recvAutData" << endl; 
		return false; 
	}
	
	//immissione valori nei buffer disposti 
	memcpy(serialized_Tpubkey, c2_total_message, serialized_Tpubkey_size);
	memcpy(c2_sign, c2_total_message + serialized_Tpubkey_size, c2_sign_size); 
	memcpy(c2_signed_message, c2_total_message, serialized_Tpubkey_size); 
	memcpy(c2_signed_message + serialized_Tpubkey_size, R, R_size); 
	
	//verifica della firma 
	EVP_MD_CTX* c2_sign_ctx = EVP_MD_CTX_new(); 
	EVP_VerifyInit(c2_sign_ctx, EVP_sha256());
	EVP_VerifyUpdate(c2_sign_ctx, c2_signed_message, c2_signed_message_size);
	ret = EVP_VerifyFinal(c2_sign_ctx, c2_sign, c2_sign_size, chatter_pubkey);




	if(ret != 1){
		cerr << "Error verifying signature client 2" << endl; 
		EVP_MD_CTX_free(c2_sign_ctx); 
		return false; 
	}
	EVP_MD_CTX_free(c2_sign_ctx);
	
	//estrazione chiave pubblica temporanea
	ret = BIO_write(Tpubkeybio, serialized_Tpubkey, serialized_Tpubkey_size ); 
	if(!ret){
		cerr << "Error writing pub key - bio" << endl; 
		return false; 
	}
	Tpubkey = PEM_read_bio_PUBKEY(Tpubkeybio, NULL, NULL, NULL); 
	
	OPENSSL_free(c2_total_message); 
	OPENSSL_free(c2_signed_message); 
	OPENSSL_free(c2_sign);
	
//Creazione messaggio da inviare autenticato (n.s.s || IV || E(Tpubkey, key) || E(key, aes_key) || DS( Tpubkey || E(Tpubkey, K)) || TAG)

	//creazione chiave simmetrica e criptaggio con chiave pubblica temporanea
	uint32_t IV_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());		
	uint32_t en_key_size = EVP_PKEY_size(Tpubkey);
	
	unsigned char* aes_key = (unsigned char*)malloc(16);
	unsigned char* crypted_aes_key = (unsigned char*)malloc(16); 
	unsigned char* IV = (unsigned char *)malloc(IV_size);
	unsigned char* en_key = (unsigned char*)malloc(en_key_size); 

	RAND_poll(); 
	RAND_bytes(aes_key, 16); 
	RAND_bytes(IV, IV_size);
	
	uint32_t envelope_size = envelope_encrypt( aes_key, 16 , Tpubkey, IV, crypted_aes_key, en_key, en_key_size); 
	
	//lettura chiave privata client
	EVP_PKEY* c1_privkey = NULL; 
	string c1_key_file_name = "./client/database/";
	c1_key_file_name.append((char*)current_client->name); 
	c1_key_file_name.append("_private.pem"); 
	FILE* c1_key_file = fopen(c1_key_file_name.c_str(), "r"); 
	if(!c1_key_file){
		cerr << "Error opening pem file" << endl; 
		return false; 
	}
	c1_privkey = PEM_read_PrivateKey(c1_key_file, NULL, NULL, NULL); 
	if(!c1_privkey){
		cerr <<"Error opening private key"<<endl; 
		return false; 
	}
	fclose(c1_key_file); 

	//dimensionamento buffer per creazione firma e firma 
	uint32_t c1_signed_message_size	= serialized_Tpubkey_size + en_key_size;
	uint32_t c1_sign_size = EVP_PKEY_size(c1_privkey); 
	uint32_t c1_total_size = nonce_length + en_key_size + envelope_size + c1_sign_size;
	
	unsigned char* c1_sign = (unsigned char*)malloc(c1_sign_size); 
	unsigned char* c1_signed_message = (unsigned char*)malloc(c1_signed_message_size);
	unsigned char* c1_total_message = (unsigned char*)malloc(c1_total_size); 
	
	memcpy(c1_signed_message, serialized_Tpubkey, serialized_Tpubkey_size); 
	memcpy(c1_signed_message + serialized_Tpubkey_size, en_key, en_key_size); 

	
	EVP_MD_CTX* c1_sign_ctx = EVP_MD_CTX_new(); 
	EVP_SignInit(c1_sign_ctx, EVP_sha256());
	EVP_SignUpdate(c1_sign_ctx, c1_signed_message, c1_signed_message_size);
	EVP_SignFinal(c1_sign_ctx, c1_sign, &c1_sign_size, c1_privkey);  
	EVP_MD_CTX_free(c1_sign_ctx); 
	EVP_PKEY_free(c1_privkey); 

	//creazione messaggio definitivo 
	memcpy(c1_total_message, IV, nonce_length); 
	memcpy(c1_total_message + nonce_length, en_key, en_key_size); 
	memcpy(c1_total_message + nonce_length + en_key_size, crypted_aes_key, envelope_size); 
	memcpy(c1_total_message + nonce_length + en_key_size + envelope_size, c1_sign, c1_sign_size);
	
	//invio
	if(!sendAutData(socket_c, c1_total_message, c1_total_size)){
		cerr << "Error handshake" <<endl; 
		return false; 	
	} 
	
	//salvataggio nel client della chiave e del IV per la comunicazione con il server
	save_key(aes_key, IV, 1, current_client); 
	
	
	//pulizia
	OPENSSL_free(c1_total_message); 
	OPENSSL_free(c1_signed_message); 
	OPENSSL_free(c1_sign);
	OPENSSL_free(aes_key);
	
	system("clear"); 
	
	cout << "Session established. You can stop the chat writing stop in the chat" << endl; 
	current_client->busy=1; //lol
	return true; 
}

int am_i_chatting(){
	return current_client->busy;
}

void change_state(int n){
	current_client->busy=n;
}

bool chat_request(){
	
	int ret; 
	
	unsigned char* c2_name = (unsigned char*)malloc(length_max_users); 
	uint32_t c2_name_size = length_max_users;
	if(!recvSecureData(socket_c, c2_name, c2_name_size, session_value)){
		cerr << "Error recvSecureData" << endl; 
		return false; 
	}
		
	cout << "chat request received from: " << c2_name << endl; 
	cout << "allow request: (y/n): " ; 
	string risposta; 
	cin >> setw(2) >> risposta; 
	cout << endl; 
		
	//valuto la decisione del client (per qualunque riposta tranne che "si" la richiesta viene rifiutata
	if(!risposta.compare("y")){
			
		if(!next_operation_for_server(socket_c, 7, session_value)){
			cerr << "Error next_operation_for_server" << endl; 
			return false; 
		}
		
		//ricezione chiave pubblica dell'altro client e deserializzazione
		int serialized_pubkey_size = 625; 
		unsigned char* serialized_pubkey = (unsigned char*)malloc(serialized_pubkey_size);		
		if(!recvAutData(socket_c, serialized_pubkey, serialized_pubkey_size, session_value)){
			cerr << "Error recvAutData" << endl;
			return false;
		}
		
		chatter_pubkey = NULL; 
		BIO *chatter_pubkeybio = BIO_new(BIO_s_mem());
		ret = BIO_write(chatter_pubkeybio, serialized_pubkey, serialized_pubkey_size); 
		if(!ret){
			cerr << "Error writing pub key bio" << endl; 
			return false; 
		}
		chatter_pubkey = PEM_read_bio_PUBKEY(chatter_pubkeybio, NULL, NULL, NULL); 
		
		cout << "successfull public key received" << endl;

		
		//inizio scambio chiave di sessione simmetrica 
		if(!handshake_called()){
			cerr << "Error handshake called" << endl; 
			return false; 
		} 
		current_client->busy=1;
	}
	else{
			
		if(!next_operation_for_server(socket_c, 5, session_value)){
			cerr << "Error next_operation_for_server" << endl; 
			return false; 
		}
	}
	
	return true; 
}

bool recvSecureData(int socket, unsigned char* data, uint32_t data_size, int session_type){
	
	int ret; 
	
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
			cerr << "Error recvAutData" << endl; 
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
	inc_iv(session_type);
//generazione oggetto per la codifica

if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
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

bool handshake_called(){

	int ret; 
	
//ricezione messaggio autenticato 
//(n.s.s || R || TAG) 

	uint32_t R_size = nonce_length; 
	unsigned char* R = (unsigned char*)malloc(R_size); 
	
	if(!recvAutData(socket_c, R, R_size, session_value)){
		cerr << "Error recvAutData" << endl; 
		return false;
	}
	
//creazione messaggio autenticato 
//(n.s.s || serialized_Tpubkey || DS(serialized_Tpubkey || R) || TAG) 

	//creazione coppia chiavi RSA (Tpubkey, Tprivkey)
	EVP_PKEY* Tprivk = EVP_PKEY_new(); 
	char* serialized_Tpubkey = NULL; 
	
	if(!create_temp_rsa_key(Tprivk)){
		cerr << "Error generating ephimeral keys" << endl; 
		return false; 
	}
	
	BIO* Tpubkeybio = BIO_new(BIO_s_mem()); 
	PEM_write_bio_PUBKEY(Tpubkeybio, Tprivk); 
	long serialized_Tpubkey_size = BIO_get_mem_data(Tpubkeybio, &serialized_Tpubkey);
	
	//recupero chiave privata per firma
	EVP_PKEY* c2_privkey = NULL; 
	string c2_key_file_name = "./client/database/";
	c2_key_file_name.append((char*)current_client->name); 
	c2_key_file_name.append("_private.pem"); 
	FILE* c2_key_file = fopen(c2_key_file_name.c_str(), "r"); 
	if(!c2_key_file){
		cerr << "Error opening the private key" << endl; 
		return false; 
	}
	c2_privkey = PEM_read_PrivateKey(c2_key_file, NULL, NULL, NULL); 
	if(!c2_privkey){
		cerr <<"Error opening the private key"<<endl; 
		return false; 
	}
	fclose(c2_key_file);
	
	//creazione buffer per messaggio 
	uint32_t c2_sign_size = EVP_PKEY_size(c2_privkey); 
	uint32_t c2_signed_message_size = serialized_Tpubkey_size + R_size; 
	uint32_t c2_total_size = serialized_Tpubkey_size + c2_sign_size; 
	
	unsigned char* c2_sign = (unsigned char*)malloc(c2_sign_size);
	unsigned char* c2_signed_message = (unsigned char*)malloc(c2_signed_message_size);
	unsigned char* c2_total_message = (unsigned char*)malloc(c2_total_size);

	memcpy(c2_signed_message, serialized_Tpubkey, serialized_Tpubkey_size); 
	memcpy(c2_signed_message + serialized_Tpubkey_size, R, R_size); 
	
	//creazione firma 
	EVP_MD_CTX* c2_sign_ctx = EVP_MD_CTX_new(); 
	EVP_SignInit(c2_sign_ctx, EVP_sha256());
	EVP_SignUpdate(c2_sign_ctx, c2_signed_message,c2_signed_message_size);
	EVP_SignFinal(c2_sign_ctx, c2_sign, &c2_sign_size, c2_privkey);  
	EVP_MD_CTX_free(c2_sign_ctx); 
	EVP_PKEY_free(c2_privkey);
	
	//creazione messaggio intero da inviare 
	memcpy(c2_total_message, serialized_Tpubkey, serialized_Tpubkey_size); 
	memcpy(c2_total_message + serialized_Tpubkey_size, c2_sign, c2_sign_size);

	//invio messaggio
	if(!sendAutData(socket_c, c2_total_message, c2_total_size)){
		cerr << "Error sendAutData" << endl; 
		return false; 
	}

//ricezione messaggio autenticato  
//(n.s.s || IV || E(Tpubkey, key) || E(key, aes_key) || DS( Tpubkey || E(Tpubkey, K)) || TAG)
	
	//creazione e dimensionamento buffer per ricezione messaggio 
	uint32_t IV_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm()); 
	uint32_t en_key_size = 256; 
	uint32_t c1_sign_size = 384; 
	uint32_t c1_signed_message_size = serialized_Tpubkey_size + en_key_size; 
	uint32_t c1_total_size = IV_size + en_key_size + 16 + c1_sign_size;

	unsigned char* IV = (unsigned char*)malloc(IV_size); 
	unsigned char* aes_key = (unsigned char*)malloc(16); 
	unsigned char* crypted_aes_key = (unsigned char*)malloc(16); 
	unsigned char* en_key = (unsigned char*)malloc(en_key_size);  
	unsigned char* c1_sign = (unsigned char*)malloc(c1_sign_size); 
	unsigned char* c1_signed_message = (unsigned char*)malloc(c1_signed_message_size); 
	unsigned char* c1_total_message = (unsigned char*)malloc(c1_total_size); 
	
	//ricezione messaggio 
	if(!recvAutData(socket_c,  c1_total_message, c1_total_size, session_value)){
		cerr << " Error recvautdata" << endl; 
		return false; 
	}
	
	//inserimento valori nei buffer
	memcpy(IV, c1_total_message, IV_size); 
	memcpy(en_key, c1_total_message + nonce_length, en_key_size); 
	memcpy(crypted_aes_key, c1_total_message + nonce_length + en_key_size, 16); 
	memcpy(c1_sign, c1_total_message + nonce_length + en_key_size + 16, c1_sign_size); 
	memcpy(c1_signed_message, serialized_Tpubkey, serialized_Tpubkey_size); 
	memcpy(c1_signed_message + serialized_Tpubkey_size, en_key, en_key_size);
	
	//verifica firma
	EVP_MD_CTX* c1_sign_ctx = EVP_MD_CTX_new(); 
	EVP_VerifyInit(c1_sign_ctx, EVP_sha256());
	EVP_VerifyUpdate(c1_sign_ctx, c1_signed_message, c1_signed_message_size);
	ret = EVP_VerifyFinal(c1_sign_ctx, c1_sign, c1_sign_size, chatter_pubkey);
	if(ret != 1){
		cerr << "Errorverifying signature" << endl; 
		EVP_MD_CTX_free(c1_sign_ctx); 
		return false; 
	}
	EVP_MD_CTX_free(c1_sign_ctx); 

	//estrazione chiave simmetrica 
	uint32_t envelope_size = envelope_decrypt(crypted_aes_key, 16, Tprivk, IV, aes_key, en_key, en_key_size); 
	
	save_key(aes_key, IV, 1,current_client); 
	
	
	system("clear"); 
	
	cout << "Session established. You can stop the chat writing stop in the chat" << endl << endl;
	current_client->busy=1; //lol
	return true; 	
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

int envelope_decrypt(unsigned char *ciphertext, int cipher_len, EVP_PKEY* privkey, unsigned char *iv, unsigned char *plaintext, unsigned char* en_key, int en_key_size){
	  
	  int len;
	  int plain_len, ret;
	  EVP_CIPHER_CTX* ctx; 

	  /* Create and initialise the context */
	  ctx = EVP_CIPHER_CTX_new();
	  
	  
	  // SealInit
	  ret = EVP_OpenInit(ctx, EVP_aes_128_gcm(), en_key, en_key_size, iv, privkey);
	  if(!ret){
		 cout << "error OpenInit" << endl; 
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


//funzione per la ricezione di un messaggio in chat 
bool recvMessage(){
	
	//ricezione dimensione messaggio  
	unsigned char* size = (unsigned char*)malloc(sizeof(uint32_t));  
	
	if(!recvAutData(socket_c, size, sizeof(uint32_t), session_value)){
		cerr << "Error recvCode" << endl; 
		return false;
	}
	
	uint32_t message_size = (uint32_t)*size; 
	unsigned char* message = (unsigned char*)malloc(message_size); 
	
	//ricezione messaggio 
	if(!recvSecureData(socket_c, message, message_size, 1)){
		cerr << "Error recvAutData" << endl; 
		return false; 
	}
	
	//conversione in stringa e stampa a video 
	char* messaggio_stampato = (char*)malloc(message_size + 1); 
	memcpy(messaggio_stampato, message, message_size); 
	messaggio_stampato[message_size] = '\0'; 
	
	cout << ">>>" << messaggio_stampato << endl << endl; 
	
	return true;  
}

//funzione per inviare un messaggio in chat
bool sendMessage(char* read_message, uint32_t message_size){

	//invio OPCODE per operazione 6
	if(!next_operation_for_server(socket_c, 6, session_value)){
		cerr << "Error next_operation_for_server" << endl; 
		return false; 
	}
	
	 //creazione messaggio 
	unsigned char* message = (unsigned char*)malloc(message_size); 
	memcpy(message, read_message, message_size); 
	
	unsigned char* size = (unsigned char*)malloc(sizeof(uint32_t)); 
	memcpy(size, &message_size, sizeof(uint32_t)); 
	
	//invio dimensione 
	if(!sendAutData(socket_c, size, sizeof(uint32_t))){
		cerr << "Error sendautdata" << endl; 
		return false; 
	}
	
	//invio messaggio 
	if(!sendSecureData(socket_c, message, message_size, 1)){
		cerr << "Error sendSecureData" << endl; 
		return false; 
	}
	
	return true; 
	
}

bool show_online_clients(){
	uint32_t list_dim = 0; 
	unsigned char* name = (unsigned char*)malloc(length_max_users);

	//OPCODE al server per la lista utenti
	if(!next_operation_for_server(socket_c,2,session_type)){
		cerr << "Error 2" << endl;
		return false;
	}

	if(!receive_for_next_operation_server(socket_c,&list_dim,session_type)){
		cerr << "error receiving the message" << endl; 
		return false;
	}
	if(list_dim == 0){
		cout << "no clients ready to chat" << endl; 
		return true; 
	}
	
	unsigned char* list = (unsigned char*)malloc(list_dim); 
	
	//ricezione della lista dei client
	// TO DO
	
	if(!recvAutData(socket_c, list, list_dim, session_type)){
		cerr << "Error recvAutList" << endl; 
		return false; 
	}

	// TO DO
	printf("you can chat with:\n");
	char* user=strtok((char*)list,"_");
	while(user!=NULL){
		printf("%s\n",user);
		user=strtok(NULL,"_");
	}

	return true; 


}

bool receive_for_next_operation_server(int socket_c,uint32_t*  rec_opcode,int session_type){
	int ret; 
	
	//preparazione dei buffer per la ricezione del messaggio e 
	// per il decriptaggio 
	uint32_t plain_size = sizeof(uint32_t); 
	uint32_t cipher_size = plain_size; 
	uint32_t total_size = nonce_length + cipher_size + tag_size;	
	
	unsigned char* aes_key = (unsigned char*)malloc(aes_key_length); 
	unsigned char* IV = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
	unsigned char* plaintext = (unsigned char*)malloc(plain_size); 
	unsigned char* ciphertext = (unsigned char*)malloc(cipher_size);
	unsigned char* tag = (unsigned char*)malloc(tag_size); 
	unsigned char* total_message = (unsigned char*)malloc(total_size);
	unsigned char* aad = (unsigned char*)malloc(nonce_length);
	unsigned char* received_seq_number = (unsigned char*)malloc(nonce_length);
	
	//ricezione messaggio
	ret = recv(socket_c, (void*) total_message, total_size, 0);
	if(ret <= 0 || ret != (int)total_size){ 
		cerr << "Error recv" << endl;
		return false;
	}
	
	//copio i valori nei buffer
	memcpy(aad, total_message, nonce_length); 
	memcpy(ciphertext, total_message + nonce_length, cipher_size);
	memcpy(tag, total_message + nonce_length + cipher_size, tag_size); 
	memcpy(received_seq_number, total_message, nonce_length); 
	
	//incremento IV e lo carico per controllare il numero ricevuto 
	inc_iv(session_type);

	/******* GET *******/

	if(session_type == session_value){
		if(!current_client->client_server_symmetric_key){
			cerr << "no previously saved key client server" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->client_server_symmetric_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client server" << endl; 
			return false;
		}
		
		if(!current_client->IV){
			cerr << "error iv missing client server" << endl; 
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
			cerr << "no previously saved key client client" << endl; 
			return false; 
		} 
		memcpy(aes_key, current_client->chat_sym_key, 16); 
		if(!aes_key){
			cerr <<"error getting the simmetric key client client" << endl; 
			return false;
		}
		
		if(!current_client->chat_IV){
			cerr << "error iv missing client client" << endl; 
			return false; 
		} 
		memcpy(IV, current_client->chat_IV, EVP_CIPHER_iv_length(EVP_aes_128_gcm())); 
		if(!aes_key){
			cerr <<"error getting iv client client" << endl; 
			return false;
		}
		
	}


	/*******************/
	
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
 		cerr << "Error Decrypt Final" << endl; 
 		return false; 
 	}
 	plaintext_len += len; 
 
 	EVP_CIPHER_CTX_free(ctx);  
	if(plaintext_len!=plain_size){
 		cerr << "Error" << endl;
 		return false; 
 	}
	
	
	//copio valore opcode ricevuto 
	memcpy(rec_opcode, plaintext, plain_size); 
	
	OPENSSL_free(total_message);
	OPENSSL_free(aes_key);
	OPENSSL_free(plaintext);
	OPENSSL_free(ciphertext);
	
	return true;
}