#include<iostream>
#include<stdlib.h>
#include<string.h>
#include <dirent.h> 
#include<openssl/pem.h>
#include<crypto.hpp>
using namespace std;

#define size 128

//Questa funzione esegue la free del database.
//0 memory leaks TESTED!
void freeDatabase(Users* database){ //TODO DA CAMBIARE
	Users* tmp=database;
	while(tmp!=NULL){
		database=database->next;
		free(tmp);
		tmp=database;
	}
}

//Cerca un utente all'interno del database.
//Se l'utente è presente ritorna la struct corrispondente, NULL altrimenti
Users* searchUser( char* string, Users* database){  //VA CAMBIATA
	Users* tmp=database;
	while(tmp!=NULL){
		if(strncmp(tmp->name,string,strlen(tmp->name))==0){
			return tmp;
		}
		tmp=tmp->next;
	}
	return NULL;
}

//Aggiunge un utente al database
//ritorna 0 in caso di successo, -1 in caso d'errore
Users* addUser(Users* new_user, Users* database){  //VA CAMBIATA
	if(database==NULL){
		database=new_user;
		return database;
		}

	Users* curr=database;
	while(curr->next!=NULL) curr=curr->next;
	curr->next=new_user;
	return database;
}

Users* LoadDatabase(char* path ,Users* database) { //TO DO VA CAMBIATA
	//Allocazione dinamica della lista
	Users* tmp=database;
	/////////////////////////////////////////////////////////////////////
	//caricamento da file
	DIR *d;
	struct dirent *dir;
	d = opendir(path);
	if (d) {
	    	while ((dir = readdir(d)) != NULL) {
	    		if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0){
	      			const char* delim="_";
	      			int name_len=strlen(dir->d_name);
	      			int dir_len=strlen(path);
	      			char* file_name=(char*)malloc(sizeof(char)*(dir_len+name_len+1));
	      			file_name=strcpy(file_name,path);
	      			file_name=strcat(file_name,dir->d_name);
	      			EVP_PKEY* pubkey;
				FILE* file = fopen(file_name, "r");
				if(!file) { /* handle error */ }
				pubkey= PEM_read_PUBKEY(file, NULL, NULL, NULL);
				if(!pubkey) { /* handle error */ }
				char* user_name=strtok(dir->d_name,delim);
				int user_name_len=strlen(user_name);
				//printf("%s\n",user_name);

				Users* new_user=(Users*)malloc(sizeof(Users));
				new_user->name=user_name;
				new_user->publickey=pubkey;
				new_user->next=NULL;
			
				tmp=addUser(new_user,tmp);
				fclose(file);
				free(file_name);
	      		} 
		}
	}
    return tmp;
}

void print_database(Users* database){
		Users* curr=database;
		while(curr!=NULL){
			cout<<curr->name<<endl;
			curr=curr->next;
		}
}

Clients* verifyOnlineUser(char* string, Clients* list){
	Clients* tmp=list;
	while(tmp!=NULL){
		if(tmp->name!=NULL && strcmp(tmp->name,string)==0 && tmp->logged==1){
			return tmp;
		}
		tmp=tmp->next;
	}
	return NULL;

}

bool save_key(unsigned char* symmetric_key, unsigned char* iv, int session_type, Clients* current_client){
//TODO CHECK
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
	return true;
}

void set_logged(Clients* new_client){
	new_client->logged=1;
}

void print_clients(Clients* clients){
		Clients* curr=clients;
		while(curr!=NULL){
			cout<<curr->name<<endl;
			curr=curr->next;
		}
}
