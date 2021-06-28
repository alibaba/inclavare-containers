/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdio.h>
#include "etls_t.h"

#define POSSIBLE_UNUSED __attribute__((unused))

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
	size_t ret;
	sgx_status_t POSSIBLE_UNUSED sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
	//assert(sgxStatus == SGX_SUCCESS);

	return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
	size_t ret;
	sgx_status_t POSSIBLE_UNUSED sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
	//assert(sgxStatus == SGX_SUCCESS);

	return ret;
}

double current_time(void)
{
	double curr;
	ocall_current_time(&curr);
	return curr;
}

int LowResTimer(void)
{
	int time;
	ocall_low_res_time(&time);
	return time;
}
