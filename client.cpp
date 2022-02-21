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
#include <unistd.h>
using namespace std;

int socket_server;  
EVP_PKEY* server_pubkey = NULL; 

void print_menu();

int main(int argc, char* argv[]){
    if(argc != 3){
		cerr << "Execute as ./client/client <Server IP> <Server Port>" << endl;
		exit(1);
	}

    char input_ip_server[16]; //argv[1]
	int input_port_server; //argv[2]
    char* name=(char*)malloc(sizeof(char)*10);
    memset(name, 0, 10);
    strcpy(input_ip_server, argv[1]);
	input_port_server = atoi(argv[2]);

    cout<<"Welcome to Online messaging service!"<<endl;
    cout<<"Please insert your name:"<<endl;
    cin>>name;

//settare il socket
    struct sockaddr_in address_server; 
    socket_server = socket(AF_INET, SOCK_STREAM, 0);
	if(socket_server < 0){
		cerr << "Error while initializing socket\n" << endl;
		exit(1);
	}

    int exit=0;
    int ret;
    int result;

    memset(&address_server, 0, sizeof(address_server)); 
	address_server.sin_family = AF_INET;
	address_server.sin_port = htons(input_port_server);
	result = inet_pton(AF_INET, input_ip_server, &address_server.sin_addr);

	if(result <= 0){
		cerr << "Error inet_pton\n" << endl;
		return -1;
	}

	result = connect(socket_server, (struct sockaddr*) &address_server, sizeof(address_server));
	if(result < 0){ 
		cerr << "Error connect socket_server\n" << endl;
		return -1;
	}

    if(login_client(socket_server,name)!=0){
    	cerr << "Error login\n" << endl;
    	if(server_pubkey != NULL){
			EVP_PKEY_free(server_pubkey);
		}
    	//quit();
    	return -1;
    }
    EVP_PKEY_free(server_pubkey);
    cout <<endl<<"connected to "  << input_ip_server << ":" << input_port_server << endl;
   
	int fdmax=0;
	int socket_ready;
	fd_set set_master,set_modifiable;

   	FD_ZERO(&set_master);
	FD_ZERO(&set_modifiable);
	FD_SET(0, &set_master); 
	FD_SET(socket_server, &set_master);
	if(socket_server > fdmax){
		fdmax = socket_server;
	}
   
	print_menu();

    //TODO implementare operazioni client
    while(!exit){

		
		set_modifiable = set_master; 
		select(fdmax + 1, &set_modifiable, NULL, NULL, NULL);

		for(socket_ready = 0; socket_ready <= fdmax; ++socket_ready){
		//si prende il comando da fare
			if(FD_ISSET(socket_ready, &set_modifiable)){
				if(socket_ready == 0){ //standard input
					if(!am_i_chatting()){
						int command;
						//print_menu();
						cin>>command;

						switch (command)
						{
						case 1:
							ret=startchat();
							if(ret==0){
								handshake_caller();
							}
							else print_menu();
							
							break;
						case 2:
							show_online_clients();
							break;
						case 3:
							quit_from_the_server();
							cout<<"disconnected"<<endl;
							return 0;
							break;
							
						
						default:
							//cout<<"Please insert a valid integer (1,2,3)";
							cout<<"";

						}
					}
					else{
						//lettura messaggio 
						char* read_message = (char*)malloc(10000); 
						uint32_t message_size = 0; 
						
						if(read_message){
							
							int c = EOF;
							
							while((c = getchar()) != '\n' && c != EOF){
								
								read_message[message_size++] = (char)c; 
								
								if( message_size == 10000){
									cout << "max size reached" << endl; 
									break; 
								}
							}
							if(message_size == 0)
								continue; 
						}
						cout << endl; 
						char* exit_chat=(char*)malloc(strlen("stop")*sizeof(char));
						exit_chat=strcpy(exit_chat,"stop");
				
						if(strncmp(exit_chat,read_message,strlen(exit_chat))==0){
							change_state(0);
							if(!next_operation_for_server(socket_server, 4, session_value)){
								cerr << "Error closing the chat" << endl; 
								continue; 
							}
							cout << "---------chat ended----------" << endl << endl; 
							print_menu(); 
							continue; 
						}
						//invio messaggio letto da terminale 
						if(!sendMessage(read_message, message_size)){
							cerr << "error: chat ended" << endl; 
							change_state(0);  
						}
					}
				}
				else if(socket_ready == socket_server){ //ricezione messsaggio dal server
					
					uint32_t received_opcode = 0; 
					
					//recupero OPCODE operazione
					if(!recvCode(socket_server, &received_opcode, session_value)){
						cerr << "Error recvCode" << endl; 
						return -1; 
					}
					
					if(received_opcode == 9){
						
						if(!chat_request()){
							cerr << "Error chat request" << endl; 
							return -1; 
						}
						cin.clear(); 
					}
					
					else if (received_opcode == 6){
						
						if(!recvMessage()){
							cerr << "Error received message" << endl; 
							return -1;  
						} 
					}
					
					else if (received_opcode == 4 && am_i_chatting()){
		
						change_state(0); 
						
						cout << "---------Chat ended----------" << endl << endl; 
						print_menu(); 
					}
				}
			}
		}
    }
	
	close(socket_server);

    return 0;
}

void print_menu(){
	printf("\nPlease insert one integer associated to the command:\n1) start chat\n2) show online clients\n3) logout from the server\n");
}

