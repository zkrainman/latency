
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <errno.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

void recvpacket(int sockfd, int recvmsg_flags)
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
	struct timeval time_user;
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
	res = recvmsg(sockfd, &msg, recvmsg_flags);
	gettimeofday(&time_user, NULL);
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
					long timediff = (time_user.tv_sec - stamp->tv_sec) * 1000000000 + (time_user.tv_usec - stamp->tv_usec) * 1000;
					std::cout << "\ttimediff: " << timediff << std::endl;
				}
				else if(cmsg->cmsg_type == SO_TIMESTAMPNS){
					struct timespec *stamp = (struct timespec *)CMSG_DATA(cmsg);
					std::cout << "SO_TIMESTAMPNS\tSW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec;
					long timediff = (time_user.tv_sec - stamp->tv_sec) * 1000000000 + (time_user.tv_usec * 1000 - stamp->tv_nsec);
					std::cout << "\ttimediff: " << timediff << std::endl;
				}
				else if(cmsg->cmsg_type == SO_TIMESTAMPING){
					struct timespec *stamp = (struct timespec *)CMSG_DATA(cmsg);
					long timediff = (time_user.tv_sec - stamp->tv_sec) * 1000000000 + (time_user.tv_usec * 1000 - stamp->tv_nsec);
					std::cout << "SO_TIMESTAMPING\tSW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec << " time_diff: " << timediff;
					stamp++;
					timediff = (time_user.tv_sec - stamp->tv_sec) * 1000000000 + (time_user.tv_usec * 1000 - stamp->tv_nsec);
					std::cout << "\tHW transformed: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec << " time_diff: " << timediff;
					stamp++;
					timediff = (time_user.tv_sec - stamp->tv_sec) * 1000000000 + (time_user.tv_usec * 1000 - stamp->tv_nsec);
					std::cout << "\tHW: " << (long)stamp->tv_sec << "." << (long)stamp->tv_nsec << " time_diff: " << timediff;
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	//
	struct sockaddr_in local_addr;
    local_addr.sin_addr.s_addr = inet_addr("172.24.1.14");
    local_addr.sin_port = htons(20000);
    local_addr.sin_family = AF_INET;
	//
	int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0){
		std::cout << "socket error!" << std::endl;
		return 0;
	}
    //
    int timestampOn = 1;
    int rc = setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, (int *)&timestampOn, sizeof(timestampOn));
    if (rc < 0) {
		std::cout << "setsockopt SO_TIMESTAMP error!" << std::endl;
		return 0;
    }
	//
    rc = bind(sockfd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr_in));
    if (rc < 0) {
        std::cout << "bind error!" << std::endl;
		return 0;
    }
	//
    std::cout << "Starting main loop." << std::endl;
	while(true) {
		recvpacket(sockfd, 0);
	}
    return rc;
}