/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "etls_socket.h"

int64_t ocall_socket(int domain, int type, int protocol)
{
	errno = 0;

	return socket(domain, type, protocol);
}

int ocall_setsockopt(int64_t sockfd,
                     int level,
                     int optname,
                     const void* optval,
                     uint32_t optlen)
{
	errno = 0;

	return setsockopt((int)sockfd, level, optname, optval, optlen);
}

int ocall_bind(int64_t sockfd, const struct etls_sockaddr_in* addr, uint32_t addrlen)
{
	errno = 0;

	return bind((int)sockfd, (const struct sockaddr*)addr, addrlen);
}

int ocall_listen(int64_t sockfd, int backlog)
{
	errno = 0;

	return listen((int)sockfd, backlog);
}

int64_t ocall_accept(int64_t sockfd,
                     struct etls_sockaddr_in* addr,
                     uint32_t addrlen_in,
                     uint32_t *addrlen_out)
{
	int ret;

	errno = 0;

	if ((ret = accept((int)sockfd, (struct sockaddr*)addr, &addrlen_in)) != -1)
	{
		if (addrlen_out)
			*addrlen_out = addrlen_in;
	}

	return ret;
}

int ocall_connect(int64_t sockfd,
                  const struct etls_sockaddr_in* addr,
                  uint32_t addrlen)
{
	errno = 0;

	return connect((int)sockfd, (const struct sockaddr*)addr, addrlen);
}

int ocall_close(int64_t fd)
{
	errno = 0;

	return close((int)fd);
}
