
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <iostream>

int main(int argc, char **argv)
{
	//
	struct sockaddr_in remote_addr;
    remote_addr.sin_addr.s_addr = inet_addr("172.24.1.14");
    remote_addr.sin_port = htons(20000);
    remote_addr.sin_family = AF_INET;
	//
	struct timeval tv;
	char packet[100];
	memset(packet, 0, sizeof(packet));
	memcpy(packet, "test", 4);
	//
	int sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0){
		std::cout << "socket error!" << std::endl;
		return 0;
	}
	//
    std::cout << "Starting main loop." << std::endl;
	while(true){
		//
		int rc = sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
		if(rc < 0){
			std::cout << "sendto error!" << std::endl;
		}
		std::cout << "packet sent!" << std::endl;
		//
		sleep(2);
	}
	//
    return 0;
}