/**  Copyright 2017 Ulascan Ersoy | Light-Net-Counter
  *  This program is free software: you can redistribute it and/or modify
  *  it under the terms of the GNU General Public License as published by
  *  the Free Software Foundation, either version 3 of the License, or
  *  (at your option) any later version.
  *
  *  This program is distributed in the hope that it will be useful,
  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *  GNU General Public License for more details.
  *
  *  You should have received a copy of the GNU General Public License
  *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *_______________________________________________________________________
  *##COMMANDS##
  * -configure $"DEVICENAME"
  * -add $MACADDR $LIMIT
  * -remove $index
  * -list 
  * -start
  * -help 
  * -about    
  * -version
  **/

/** INCLUDE **/
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <pcap.h>
#include <time.h>

/**GLOBALS**/
#define DIR_CONFIG ".lnc-config" 
#define ABOUT_TXT  "2017 Ulascan Ersoy , Light Weight Network Tracker"
#define HELP_TXT " -configure $DEVICENAME $FILEDIR \n -add $MACADDR $Limit \n -list \n -remove $index \n -start \n -about \n -version"
#define VERSION    "V0.0.1"
#define COMMAND(a)(strcmp(argv[1] , a) == 0)
#define isEqual(a , b)(strcmp(a , b) == 0 )

unsigned int time_out   = 0;
unsigned int packet_lim = 0;
unsigned int min_diff = 0 , sec_diff = 5 , hour_diff = 0;

/**Time and date related stuff**/
time_t t;
struct tm tm;
struct tm begin_time;
char* curDate;

/**Report File Related stuff**/
long int d_offset = 0; //Offset of our data in the file

/**PROTOTYPES**/
int _configure(char* device , char* dir);
int start();
void updateDate();
void packet_handler(u_char* args , const struct pcap_pkthdr *packet_header , const u_char *packet_body);
void _ntoa(const struct ether_header* mac , char* dest , char* src);
char* input(FILE* f);

struct {
	char* device_name;
	char* last_reset;
	char* file_dir;
	unsigned long long int session_total;
	
}Configuration;

unsigned int usr_size = 0;
struct List{
	
	char *ALIAS;
	char *MAC;
	/**In bytes**/
	unsigned long long int Upload;
	unsigned long long int Download;
	unsigned long long int limit;

}*user_list;
/**FUNCTIONS RELATED TO LIST**/
int _usradd(char* ALIAS , char* MAC , char* limit , char list_add);//Adds to list | limit = 0 means no limit
int _usrremove(char* index);//Removes from the list
int _usrLookupMAC(char* MAC);//Argument in dotted notation! Looks for the given MAC address , if found returns the index if not returns -1
int _usrlist();//List 
int _usrsave();//Save to the report file

void lnc_init(){
	
	Configuration.session_total = 0;
	Configuration.last_reset = calloc(sizeof(char) , 11);
	t = time(NULL);
	curDate = calloc(sizeof(char) , 10);
	updateDate();
	/**Allocate the list**/
	user_list = calloc(1 , sizeof(struct List));
	
	begin_time = *localtime(&t);


}//End of lnc_init

int main(int args , char** argv){
	
	lnc_init();
	
	
	//Check if there are enough arguments
	if(args < 2){
		
		puts("Not enough Arguments! -help for help");
		return -1;
	}

	if(COMMAND("-help")){
		
		puts(HELP_TXT);
		return 0;

	}else if(COMMAND( "-about")){
		
		puts(ABOUT_TXT);
		return 0;

	}else if(COMMAND("-version")){
		
		puts(VERSION);
		return 0;

	}else if(COMMAND("-configure")){
		
		return _configure(argv[2] , argv[3]);

	}else if(COMMAND("-start")){
		
		return start();
	
	}else if(COMMAND("-add")){
		
		if(args < 4){
		
			puts("Not enough Arguments! -help");
			return -1;
		
		}
		else return _usradd(argv[2] , argv[3] , argv[4] , 1);

	}else{

		puts("Not a command! Try -help.");
		return 2;

	}	
	


}//End of main

/** -1 failed , 0 success **/
int _configure(char* device , char* dir){

	FILE* f = fopen(DIR_CONFIG , "w+");

	if(!f){
		puts("File Error!");
		return -1;
	}
	
	if(dir == NULL){
		
		puts("Invalid file dir!");
		return -1;

	}

	bpf_u_int32 ip_raw;
	bpf_u_int32 submask_raw;
	int return_code;
	char error_buf[PCAP_ERRBUF_SIZE];

	return_code = pcap_lookupnet(device , &ip_raw , &submask_raw , error_buf);
	if(return_code == -1){
		
		printf("%s\n" , error_buf);
		return -1;

	}

	fprintf(f , "DeviceName%c%s\n" , 61 ,device);
	updateDate();
	fprintf(f , "LastReset%c%s\n"  , 61 ,curDate);	
	fprintf(f , "FileDir%c%s\n"    , 61 ,dir);
	
	
	fclose(f);

puts("Configuration Complete!");
return 0;
}

int start(){
	
	FILE* f_config = fopen(DIR_CONFIG , "r+");

	if(!f_config){
		
		puts("Config File not found! use -configure");
		return -1;

	}
	
	/**Load the config**/
	int k = 0;
	while(k == 0){
		
		char* line = calloc(sizeof(char) , 128);
		char* flag = calloc(sizeof(char) , 64);
		char* var  = calloc(sizeof(char) , 64);
		
		if(fscanf(f_config , "%s" , line) == EOF)break;	
		
		for(int i = 0 ; i < strlen(line) ; i++)if(line[i] == 61)line[i]=32;
		
		sscanf(line , "%s %s" , flag , var);

		if(strcmp(flag , "DeviceName") == 0){

			Configuration.device_name = calloc(sizeof(char) , strlen(var));
			Configuration.device_name = var;

			printf("%s is set to '%s'\n" , flag , Configuration.device_name);

		}else if(strcmp(flag , "LastReset") == 0){
			
			Configuration.last_reset = var;		
			printf("%s is set to %s \n" , flag , Configuration.last_reset);

		}else if(strcmp(flag , "FileDir") == 0){

			Configuration.file_dir = var;
			printf("%s is set to '%s'\n" , flag ,Configuration.file_dir);

		}else if(strcmp(flag , "Track") == 0){
			
			char *MAC  = calloc(sizeof(char) , 17 ),
			     *limit= calloc(sizeof(char) , 64 );
			
			fscanf(f_config , "%s%s" , MAC , limit);
			_usradd(var , MAC , limit , 0);		
			printf("Track[%d]: %s %s %s\n" , usr_size-1 , var , MAC , limit);
							
		}else{

			printf("%s is an unknown option! Ignoring.\n" , flag);

		}//End of Command matching

	}//end of while
	
	fclose(f_config);

	/**Check if the config is valid**/
	
	bpf_u_int32 ip_raw;
	bpf_u_int32 submask_raw;
	int return_code;
	char error_buf[PCAP_ERRBUF_SIZE];
	
	return_code = pcap_lookupnet(Configuration.device_name , &ip_raw , &submask_raw , error_buf);
	
	char data_found = 0;

	if(return_code == -1){
		
		printf("%s\n" , error_buf);
		return -1;
	}

	FILE* f_report = fopen(Configuration.file_dir , "r+");
	if(!f_report){
		
		fprintf(stderr , "Report file not found! '%s' Creating a new one!\n" , Configuration.file_dir);
		f_report = fopen(Configuration.file_dir , "w+");
			
	}else{
		/**Load todays data**/
      		char ch , *date_str  = calloc(sizeof(char) , 8);

		while(EOF!=(ch=fgetc(f_report))){
		
			/**ASCII 35 -> "#"**/
			if(ch==35){
				
				d_offset = ftell(f_report);
				fgets(date_str , 8 , f_report);


			}//End of if

			updateDate();
			if(isEqual(date_str , curDate)){
						
				data_found = 1;
				break;
			}

		}
		

	}//End of if
	
	/**Load the data WIP**/
	while(data_found == 1){
		
		char *_name= calloc(sizeof(char) ,128),
		     *_mac = calloc(sizeof(char) , 17);
		unsigned long long int download , upload;
		int _ind;

		if(EOF==fscanf(f_report , "%s %s %llu %llu" , _name , _mac , &download , &upload))break;
		
		
		if((_ind = _usrLookupMAC(_mac)) != -1){
			
			user_list[_ind].Download = download;
			user_list[_ind].Upload   = upload;

		}
	
	}//End of loading

	_usrlist();
			


	/**START TRACKING**/

	/**Open Device for live capturing**/

	struct pcap_pkthdr packet_header;
	pcap_t *handle;
	handle = pcap_open_live(Configuration.device_name , BUFSIZ , packet_lim , time_out , error_buf);
	/**Check if the packet is Valid**/
	if(handle == NULL){
		
		fprintf(stderr , "Couldn't open device %s %s\n" , Configuration.device_name , error_buf);
		return -1;
	}

	/**Handle packets**/
	pcap_loop(handle , 0 , packet_handler , NULL);



return 0;
}//End of start

void updateDate(){
	
	t = time(NULL);
	tm = *localtime(&t);
	sprintf(curDate , "%d%d%d" , tm.tm_year+1900 , tm.tm_mon + 1 , tm.tm_mday);
	
}//End of update Date

char* input(FILE* f){

	int size = 15;
	int ch;
	char* str;
	int len = 0;

	str = realloc(NULL , sizeof(char) * size);

	if(!str)return str;

	while(EOF!=(ch=fgetc(f)) && ch!='\n'){
		
		str[len++] = ch;
		if(len == size)str = realloc(str , sizeof(char) * (size+=16));

	}//End of while

str[len++] = '\0';
return realloc(str , sizeof(char) * size);
}//End of input

void packet_handler(u_char* args , const struct pcap_pkthdr *packet_header , const u_char *packet_body){
	 
	int data = 0 , _temp = 0;
	Configuration.session_total+= (data=packet_header->len);
//	printf("Total : %d\n" , Configuration.session_total);
	
	struct ether_header *eth;

	eth = (struct ether_header*) packet_body;
	char destMac[18];
	char  srcMac[18];

	_ntoa(eth , destMac , srcMac);
	
	
	//Don't bother if the tracking list is empty just update the total
	if(usr_size != 0){

	if((_temp = _usrLookupMAC(destMac))!= -1){
		
		user_list[_temp].Download+=data;

	}	

	if((_temp = _usrLookupMAC(srcMac))!= -1){

		user_list[_temp].Upload+=data;

	}

	}//End of if
	
	/**Check for routing**/
	t = time(NULL);
	struct tm now = *localtime(&t);
	 
	if((now.tm_hour - begin_time.tm_hour >= hour_diff) && (now.tm_min - begin_time.tm_min >= min_diff) && (now.tm_sec - begin_time.tm_sec >= sec_diff)){
		
		/**Routine here | Saving | Checking for bans | etc**/
		_usrsave();
		_usrlist();
	begin_time = now;
	}//End of routine

}//End of packet_handler
//0 = just add to list | 1 = add to the file as well
int _usradd(char* ALIAS , char* MAC , char* limit , char list_add){
	
	/**Check whether the arguments are valid**/
	if(strlen(ALIAS) > 128)ALIAS[128] = '\0'; //If the alias is too long, omit
	if(strlen(MAC)!=17){
		
		fprintf(stderr , "Invalid Mac Address Format!");
		return -1;

	}
	
	unsigned long long int _limit = atoi(limit);
	/**Add and allocate**/
	usr_size++;
	user_list = realloc(user_list , (sizeof(unsigned long long int) + 132) * usr_size+1);	
	user_list[usr_size-1].ALIAS = calloc(sizeof(char),  128);
	user_list[usr_size-1].MAC   = calloc(sizeof(char),  6  ); 
	user_list[usr_size-1].ALIAS = ALIAS;
	user_list[usr_size-1].MAC   = MAC;
	user_list[usr_size-1].limit = _limit;
	user_list[usr_size-1].Download = 0;
	user_list[usr_size-1].Upload   = 0;
	/**Add to the file**/
	if(list_add == 1){
		FILE* f = fopen(DIR_CONFIG , "a");
		fprintf(f , "Track=%s %s %llu\n" , ALIAS , MAC , _limit);
		fclose(f);
	}

return 0;
}//End of add

int _usrremove(char* index){
	
	int _index = atoi(index);
	if(usr_size == 0){
		
		puts("List is already empty");
		return -1;

	}//End of if
	if(_index < 0 || _index > usr_size){
		
		puts("Invalid Index!");
		return -1;

	}//End of if
	
	user_list[_index] = user_list[usr_size-1];//Swap the last element with the removed one
	usr_size--;
	user_list = realloc(user_list , sizeof(struct List) * usr_size + 1);
	
}//End of remove

int _usrLookupMAC(char* MAC){
	
	if(strlen(MAC) < 17){
		
		fprintf(stderr , "Invalid Mac format!");
		return -1;

	}

	for(int i = 0 ;  i < usr_size ; i++)if(isEqual(user_list[i].MAC , MAC))return i;

	return -1;

}//End of Lookup MAC

int _usrlist(){

	for(int i = 0 ; i < usr_size ; i++)printf("[%d] : %s %s Down:%lld Up:%lld Limit:%lld\n",i, 
									      user_list[i].ALIAS,
									      user_list[i].MAC,
									      user_list[i].Download,
									      user_list[i].Upload,
									      user_list[i].limit);

}//End of list

void _ntoa(const struct ether_header* mac , char* dest , char* src){

	sprintf(dest , "%02x:%02x:%02x:%02x:%02x:%02x" , mac->ether_dhost[0] , mac->ether_dhost[1] , mac->ether_dhost[2],
		       				       	 mac->ether_dhost[3] , mac->ether_dhost[4] , mac->ether_dhost[5]);

	sprintf(src  , "%02x:%02x:%02x:%02x:%02x:%02x" , mac->ether_shost[0] , mac->ether_shost[1] , mac->ether_shost[2],
		    		  			 mac->ether_shost[3] , mac->ether_shost[4] , mac->ether_shost[5]);

}

int _usrsave(){

	FILE* f = fopen(Configuration.file_dir , "rb+");

	fseek(f , 0 , SEEK_END);
	unsigned long int f_size = ftell(f);
	fseek(f , 0 , SEEK_SET);
	char* str = calloc(sizeof(char) , f_size);
	fread(str , d_offset , 1 , f);
	fclose(f);
	
	f = fopen(Configuration.file_dir , "wb+");
	/**Write the old stuff**/	
	fwrite(str , strlen(str) , 1 , f);
	updateDate();
	fwrite("#" , 1 , 1 , f);
	fwrite(curDate , strlen(curDate) , 1 , f);
	fwrite("\n" , 1 , 1 , f);

	for(int i = 0 ; i < usr_size ; i++){
		
		char* temp = calloc(sizeof(char) , 256);
		sprintf(temp ,"%s %s %llu %llu\n" ,user_list[i].ALIAS , user_list[i].MAC , user_list[i].Download , user_list[i].Upload);
		fwrite(temp , strlen(temp) , 1 , f);
		

	}
	

	fclose(f);
return 0;
}//end of usr save
