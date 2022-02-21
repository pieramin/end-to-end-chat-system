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
#include <unistd.h>
using namespace std;

struct sockaddr_in address_server, address_client;
int socket_listener, socket_client;  
int main(int argc, char*argv[]) {

	if(argc != 2){
			cerr << "Execute as ./server/server <Server Port>\n" << endl;
			return -1;
	}

	int address_length; 
	int input_port_server; 
	int result;
	int socket_ready;
	fd_set set_master, set_modifiable; 
	int fdmax = 0;
	input_port_server = atoi(argv[1]);
	if(input_port_server <= 1024  ||  input_port_server > 0xFFFF){ 
		cout <<"Server port not valid\n";
		exit(1);
	}


	init();
	socket_listener = socket(AF_INET, SOCK_STREAM, 0); 

	memset(&address_server, 0, sizeof(address_server)); //pulizia 
	address_server.sin_family = AF_INET;
	address_server.sin_port = htons(input_port_server);
	address_server.sin_addr.s_addr = INADDR_ANY;

	result = bind(socket_listener, (struct sockaddr*) &address_server, sizeof(address_server));
	if(result == -1){ 
		cerr << "Error bind socket_listener\n" << endl;
		exit(1);
	}
	cout <<"Socket socket_listener ready.\n";

	result = listen(socket_listener, 10);
	if(result == -1){
		cerr << "Errore listen socket_listener\n" << endl;
		exit(1);
	}
	cout <<"Socket socket_listener waiting.\n";


	FD_ZERO(&set_master);
	FD_ZERO(&set_modifiable);
	FD_SET(socket_listener, &set_master);
	if(socket_listener > fdmax){
		fdmax = socket_listener;
	}
	int exit=0;
	while(!exit){
		set_modifiable = set_master; 
		select(fdmax + 1, &set_modifiable, NULL, NULL, NULL);

		for(socket_ready = 0; socket_ready <= fdmax; ++socket_ready){ 
			
			if(FD_ISSET(socket_ready, &set_modifiable)){
				
				if(socket_ready == socket_listener){ 

					address_length = sizeof(address_client);
					socket_client = accept(socket_listener, (struct sockaddr*) &address_client, (socklen_t*) &address_length);
					FD_SET(socket_client, &set_master);
					if(socket_client > fdmax){
						fdmax = socket_client;
					}
					
					if(login(socket_client)!=0){
						cerr << "Error login"<<endl; 
						FD_CLR(socket_client,&set_master);
						disconnect_client(socket_client); 
						close(socket_client);
					}
					
				}
				else{ //entro nell'else quando qualche socket all'interno del set è pronto, cioè quando un client ha inviato un comando da eseguire 
					
					uint32_t opcode = 0;  
					int c1_socket = socket_ready;
					Clients* tmp=NULL;
					//individuazione di quale client ha inviato il comando per lavorare sul suo oggetto Client 
					tmp=get_client(c1_socket);
					if(tmp==NULL){
						cerr << "Error: client not found" << endl; 
						return -1; 
					}
					cout << endl << "managing request from: "<<tmp->name<<endl; 
					 
					//ricevo l'OPCODE dell'operazione 
					if(!recvCode(c1_socket, &opcode, session_value)){
						cerr << "Error: disconnecting client" << endl;
						if(tmp->busy){
							 if(!end_chat(tmp))
									cerr << "Errore end_chat" << endl; 
						} 
						FD_CLR(c1_socket,&set_master);
						disconnect_client(c1_socket); 
						close(c1_socket);
						continue; 
					}
					
					//gestisco la richiesta a seconda del valore dell'OPCODE 
					 switch(opcode){
						
						case 3: 
							cout << "disconnecting: "<< tmp->name<<endl; 
							FD_CLR(c1_socket,&set_master);
							disconnect_client(c1_socket); 
							close(c1_socket);
							break; 
						
						case 2:
						{
							if(!on_clients(c1_socket)){
								cerr << "Error on_clients" << endl;
								break; 
							}
							cout << "list send" << endl; 
							break; 
						}	
						case 1: 
						{	
							int c2_socket = 0; 
							int esito = 0; 
							if(!StartChat(c1_socket, &c2_socket, &esito)){
								cerr << "Error startchat" << endl;
								break; 
							}
							
							if(esito == 5){ //chat request denied
								cout << "chat request denied" << endl << endl; 
								break;
							}
							
							Clients* client2=get_client(c2_socket);
							if(client2==NULL){
								cerr << "Error: client not found" << endl; 
								return -1; 
							}
							if(!ClientHandshake(c1_socket, c2_socket)){
								cerr << "Error ClientHandshake" << endl; 
								tmp->busy=0;
								client2->busy=0;
							}
							
							break;
						}	
						case 6: //message
						{
							if(!ExchangeMessage(c1_socket)){
								cerr << "error exchanging message from: "<< get_client(c1_socket)->name;
								 
								
								if(!end_chat(get_client(c1_socket)))
									cerr << "Error end_chat" << endl; 		
							}
			
							break; 
						}
						case 4: 
							if(!end_chat(tmp))
								cerr << "Errore end_chat" << endl; 
							break;
						
						default:
							cout << "code not found" << endl; 
							break; 
					} 

				}
			}
		}
				
		
		//login(socket_client);
		//close(socket_client);
	}
	return 0;
}