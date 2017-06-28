
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <fcntl.h>
#include <linux/net_tstamp.h>
#include <errno.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#ifndef SIOCSHWTSTAMP
# define SIOCSHWTSTAMP 0x89b0
#endif

void recvpacket(int sockfd, int recvmsg_flags, struct timeval * time_user)
{
	//
	char data[256];
	struct msghdr msg;
	struct iovec entry;
	struct sockaddr_in from_addr;
	struct {
		struct cmsghdr cm;
		char control[512];
	} control;
	int res;
	//
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	msg.msg_name = (caddr_t)&from_addr;
	msg.msg_namelen = sizeof(from_addr);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);
	//
	res = recvmsg(sockfd, &msg, recvmsg_flags|MSG_DONTWAIT);
	if (res < 0) {
		printf("%s %s: %s\n", "recvmsg", (recvmsg_flags & MSG_ERRQUEUE) ? "error" : "regular", strerror(errno));
	} 
	else {
		struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
		for (; cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)){
			std::cout << " cmsg_len: " << cmsg->cmsg_len << " cmsg_level: " << cmsg->cmsg_level << " cmsg_type: " << cmsg->cmsg_type << std::endl;
			if (cmsg->cmsg_level == SOL_SOCKET) {
				if(cmsg->cmsg_type == SO_TIMESTAMP){
					struct timeval *stamp = (struct timeval *)CMSG_DATA(cmsg);
					std::cout << "SO_TIMESTAMP\tSW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_usec;
					long timediff = (stamp->tv_sec - time_user->tv_sec) * 1000000000 + (stamp->tv_usec - time_user->tv_usec) * 1000;
					std::cout << "\ttimediff: " << timediff << std::endl;
				}
				else if(cmsg->cmsg_type == SO_TIMESTAMPNS){
					struct timespec *stamp = (struct timespec *)CMSG_DATA(cmsg);
					std::cout << "SO_TIMESTAMPNS\tSW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec;
					long timediff = (stamp->tv_sec - time_user->tv_sec) * 1000000000 + (stamp->tv_nsec - time_user->tv_usec * 1000);
					std::cout << "\ttimediff: " << timediff << std::endl;
				}
				else if(cmsg->cmsg_type == SO_TIMESTAMPING){
					struct timespec *stamp = (struct timespec *)CMSG_DATA(cmsg);
					long timediff = (stamp->tv_sec - time_user->tv_sec) * 1000000000 + (stamp->tv_nsec - time_user->tv_usec * 1000);
					std::cout << "SO_TIMESTAMPING\tSW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec << " time_diff: " << timediff;
					stamp++;
					timediff = (stamp->tv_sec - time_user->tv_sec) * 1000000000 + (stamp->tv_nsec - time_user->tv_usec * 1000);
					std::cout << "\tHW transformed: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec << " time_diff: " << timediff;
					stamp++;
					timediff = (stamp->tv_sec - time_user->tv_sec) * 1000000000 + (stamp->tv_nsec - time_user->tv_usec * 1000);
					std::cout << "\tHW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec << " time_diff: " << timediff;
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	//
	struct sockaddr_in remote_addr;
    remote_addr.sin_addr.s_addr = inet_addr("172.24.1.14");
    remote_addr.sin_port = htons(20000);
    remote_addr.sin_family = AF_INET;
	//
	int sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0){
		std::cout << "socket error!" << std::endl;
		return 0;
	}
	//
	int rc = bind(sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in));
	if (rc < 0) {
		std::cout << "bind error. ret = " << rc << std::endl;
	}
	//
	struct ifreq hwtstamp;
	struct hwtstamp_config hwconfig, hwconfig_requested;
	memset(&hwtstamp, 0, sizeof(hwtstamp));
	strncpy(hwtstamp.ifr_name, "em1", sizeof(hwtstamp.ifr_name));
	hwtstamp.ifr_data = (char *)&hwconfig;
	memset(&hwconfig, 0, sizeof(hwconfig));
	hwconfig.tx_type = HWTSTAMP_TX_ON ;
	hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;
	hwconfig_requested = hwconfig;
	rc = ioctl(sockfd, SIOCSHWTSTAMP, &hwtstamp);
	if (rc < 0) {
		std::cout << "ioctl error SIOCSHWTSTAMP. ret = " << rc << std::endl;
	}
	//
    int so_timestamping_flags = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
    rc = setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags, sizeof(so_timestamping_flags));
    if (rc < 0) {
		std::cout << "setsockopt SO_TIMESTAMPING error!" << std::endl;
		return 0;
    }
	//
    struct timeval time_user;
	struct timeval tv;
	fd_set readfds, errorfs;
	char packet[100];
	memset(packet, 0, 100);
	memcpy(packet, "test", 4);
	//
    std::cout << "Starting main loop." << std::endl;
	while(true){
		FD_ZERO(&readfds);
		FD_ZERO(&errorfs);
		FD_SET(sockfd,&readfds);
		FD_SET(sockfd, &errorfs);
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		rc = select(sockfd+1,&readfds,NULL,&errorfs,&tv);
		if (rc > 0){
			//gettimeofday(&time_user, 0);
			recvpacket(sockfd, 0, &time_user);
			recvpacket(sockfd, MSG_ERRQUEUE, &time_user);
		}
		else{
			gettimeofday(&time_user, 0);
			rc = sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
			if(rc < 0){
				std::cout << "sendto error!" << std::endl;
			}
		}
	}
	//
    return rc;
}