#ifndef _ETLS_SOCKET_H_
#define _ETLS_SOCKET_H_

#include <sys/types.h>

#define ETLS_AF_INET 2
#define ETLS_SOCK_STREAM 1
#define ETLS_SOL_SOCKET 1
#define ETLS_SO_REUSEADDR 2

// Define in_addr
struct etls_in_addr
{
    uint32_t s_addr;
};

// Define sockaddr_in
struct etls_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	struct etls_in_addr sin_addr;
	uint8_t sin_zero[8];
};



// Define sockaddr
struct etls_sockaddr
{
	uint16_t sa_family;
	char sa_data[14];
};

#endif
