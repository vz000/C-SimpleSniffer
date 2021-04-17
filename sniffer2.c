#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip.h>
#include<linux/if_ether.h>
#include<pthread.h> 
#include<unistd.h>
#define MAXBUF 1500

FILE *logs;
char netC[10];
int proTyp[7] = {0}; //0=ICMPv4 1=IGMP 2=IP 3=TCP 4=UDP 5=IPv6 6=OSPF
int sizeSummary[5] = {0}; //0=0-159 1=160-639 2=640-1279 3=1280-5119 4=5120 o mayor
uint16_t protocoloFrame;
uint16_t protocoloIP;
int seg = 1;
unsigned char buffer[MAXBUF];
int frameload = 0, size = 0;

int ProtocolType (uint16_t typeOf){
	switch(typeOf){	
			case 2048:
				return 1;
			default: 
				return 0;
	}
}

void protocoloSuperior(uint8_t protocoloSup){
	fprintf(logs,"\n Protocolo capa superior: ");
	switch(protocoloSup){
		case 1:
			fprintf(logs,"ICMP");
			proTyp[0]++;
			break;
		case 2:
			fprintf(logs,"IGMP");
			proTyp[1]++;
			break;
		case 4:
			fprintf(logs,"IP");
			proTyp[2]++;
			break;
		case 6:
			fprintf(logs,"TCP");
			proTyp[3]++;
			break;
		case 17:
			fprintf(logs,"UDP");
			proTyp[4]++;
			break;
		case 41:
			fprintf(logs,"IPv4");
			proTyp[5]++;
			break;
		case 89:
			fprintf(logs,"OSPF");
			proTyp[6]++;
			break;
			
	}
}

void typeServ(uint8_t servicio){
	fprintf(logs,"\n Tipo de servicio: ");
	switch(servicio){
		case 0:
			fprintf(logs,"De rutina");
			break;
		default:
			fprintf(logs,"%d",servicio);
			
	}
}

void sizeSum(int totSize) {
	if(totSize >= 0 && totSize <=159){
		sizeSummary[0]++;
	}
	if(totSize >=160 && totSize <=639) {
		sizeSummary[1]++;
	}
	if(totSize >= 640 && totSize <= 1279) {
		sizeSummary[2]++;
	} 
	if(totSize >= 1280 && totSize <= 5119) {
		sizeSummary[3]++;
	}
	if(totSize >= 5120){
		sizeSummary[4]++;
	}
}
void etherHeader(unsigned char *trama, int len) {
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	int isv4;
	char dest[14],orig[14] = {'\0'};
	int headerLen, cargaUtil;
	struct sockaddr_in source;
	struct sockaddr_in destination;
	memset(&source,0,sizeof(source));
	memset(&destination,0,sizeof(destination));
	if(len > 45)
	{
		ethernet_header = (struct ethhdr *)trama;
		protocoloFrame = htons(ethernet_header->h_proto);
		isv4 = ProtocolType(protocoloFrame);
		if(isv4 == 1) {
			ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
			source.sin_addr.s_addr = ip_header->saddr;
			destination.sin_addr.s_addr = ip_header->daddr;
			strcpy(orig,inet_ntoa(source.sin_addr));
			strcpy(dest,inet_ntoa(destination.sin_addr));
			
			fprintf(logs,"\n -------- Segmento %d -------- \n",seg);
			headerLen = ((unsigned int)ip_header->ihl)*4;
			fprintf(logs,"\n Longitud de cabecera en bytes: %d",headerLen);
			typeServ(ip_header->tos);
			fprintf(logs,"\n Longitud total del datagrama IP en bytes: %d",ntohs(ip_header->tot_len));
			sizeSum(ntohs(ip_header->tot_len));
			cargaUtil = ntohs(ip_header->tot_len) - headerLen;
			fprintf(logs,"\n Longitud de carga util: %d",cargaUtil);
			protocoloSuperior(ip_header->protocol);
			fprintf(logs,"\n Direccion IP fuente: %s",inet_ntoa(source.sin_addr));
			fprintf(logs,"\n Direccion IP destino: %s",inet_ntoa(destination.sin_addr));
			seg++;
		}
	}
}

void *capturador(void *args){
    logs = fopen("sniffer.txt","a+");
    if(logs==NULL) {
	printf("\n Error al abrir el archivo. ");
    }
    etherHeader(buffer, size);
}

void *analizador(void *args){
	int packet = 0, i = 0;
	int saddr_size;
	struct sockaddr saddr;

	printf("Numero de paquetes a capturar: \n");
	scanf("%d",&packet);
	
	printf("Nombre de la tarjeta de red: \n");
	scanf("%s",netC);

	int s = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(s == -1)
	{
		perror("Error en socket");
		exit(1);
	}

	struct ifreq ethreq;
	strncpy (ethreq.ifr_name, netC, IFNAMSIZ);
	ioctl(s,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl(s, SIOCSIFFLAGS, &ethreq);
	
	printf("\n Analizando... \n");
	while(i<packet) {
		saddr_size = sizeof saddr;
		size = recvfrom(s, buffer, MAXBUF, 0 , &saddr , &saddr_size);	
		pthread_t captures; 
		pthread_create(&captures,NULL,capturador, NULL);
		pthread_join(captures,NULL);
		i++;
	}
	fprintf(logs,"\n ESTADISTICAS: ");
	fprintf(logs,"\n Numero de paquetes capturados de cada uno de los protocolos de la capa superior: ");
	fprintf(logs,"\n ICMP: %d IGMP: %d IP: %d TCP: %d UDP: %d IPv6: %d OSPF: %d ",proTyp[0],proTyp[1],proTyp[2],proTyp[3],proTyp[4],proTyp[5],proTyp[6]);
	fprintf(logs,"\n Numero de paquetes segun su tamaño: ");
	fprintf(logs,"\n 0-159: %d 160-639: %d 640-1279: %d 1280-5119: %d 5120 o mayor: %d",sizeSummary[0],sizeSummary[1],sizeSummary[2],sizeSummary[3],sizeSummary[4]);
}

int main() {
	pthread_t analize; 
	pthread_create(&analize,NULL,analizador,NULL);
	pthread_join(analize,NULL);
	char command[50];
	snprintf(command,sizeof(command),"/sbin/ifconfig %s -promisc",netC);
	system(command);
	//mostrar(direcc);
	printf("\n Analisis terminado. \n Registros en: sniffer.txt \n");
	return 0;
}
