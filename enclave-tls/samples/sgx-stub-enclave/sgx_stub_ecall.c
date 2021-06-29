/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#include "enclave-tls/api.h"
#include "sgx_stub_t.h"

int ecall_etls_server_startup(sgx_enclave_id_t enclave_id,
                              enclave_tls_log_level_t log_level,
                              char *attester_type,
                              char *verifier_type,
                              char *tls_type,
                              char *crypto_type,
                              unsigned long flags,
                              uint32_t s_ip,
                              uint16_t s_port)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strncpy(conf.attester_type, attester_type, strlen(attester_type));
	strncpy(conf.verifier_type, verifier_type, strlen(verifier_type));
	strncpy(conf.tls_type, tls_type, strlen(tls_type));
	strncpy(conf.crypto_type, crypto_type, strlen(crypto_type));
	conf.enclave_id = enclave_id;
	conf.flags = flags;

	int64_t sockfd;
	int sgx_status = ocall_socket(&sockfd,
                                      ETLS_AF_INET,
                                      ETLS_SOCK_STREAM,
                                      0);
	if (sgx_status != SGX_SUCCESS || sockfd < 0) {
		ETLS_ERR("Failed to call socket() %#x %d\n",
                         sgx_status, sockfd);
		return -1;
	}

	int reuse = 1;
	int ocall_ret = 0;
	sgx_status = ocall_setsockopt(&ocall_ret,
                                      sockfd,
                                      ETLS_SOL_SOCKET,
                                      ETLS_SO_REUSEADDR,
                                      (const void *)&reuse,
                                      sizeof(int));
	if (sgx_status != SGX_SUCCESS || ocall_ret < 0) {
		ETLS_ERR("Failed to call setsockopt() %#x %d\n",
	                 sgx_status, ocall_ret);
		return -1;
	}

	struct etls_sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = ETLS_AF_INET;
	s_addr.sin_addr.s_addr = s_ip;
	s_addr.sin_port = s_port;

	/* Bind the server socket */
	sgx_status = ocall_bind(&ocall_ret,
                                sockfd,
                                (struct etls_sockaddr *)&s_addr,
                                sizeof(s_addr));
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		ETLS_ERR("Failed to call bind(), %#x %d\n",
                         sgx_status, ocall_ret);
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	sgx_status = ocall_listen(&ocall_ret, sockfd, 5);
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		ETLS_ERR("Failed to call listen(), %#x %d\n",
                       sgx_status, ocall_ret);
		return -1;
	}

	/* Enclave-tls init */
	libenclave_tls_init();
	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Failed to initialize enclave tls %#x\n", ret);
		return -1;
	}

	/* Accept client connections */
	struct etls_sockaddr_in c_addr;
	uint32_t addrlen_in = sizeof(c_addr);
	uint32_t addrlen_out;
	while (1) {
		ETLS_INFO("Waiting for a connection ...\n");

		int64_t connd;
		sgx_status = ocall_accept(&connd,
                                          sockfd,
                                          (struct sockaddr *)&c_addr,
                                          addrlen_in,
                                          &addrlen_out);
		if (sgx_status != SGX_SUCCESS || connd < 0) {
			ETLS_ERR("Failed to call accept() %#x %d\n",
                                 sgx_status, connd);
			return -1;
		}

		ret = enclave_tls_negotiate(handle, connd);
		if (ret != ENCLAVE_TLS_ERR_NONE) {
			ETLS_ERR("Failed to negotiate %#x\n", ret);
			goto err;
		}

		ETLS_DEBUG("Client connected successfully\n");

		char buf[256];
		size_t len = sizeof(buf);
		ret = enclave_tls_receive(handle, buf, &len);
		if (ret != ENCLAVE_TLS_ERR_NONE) {
			ETLS_ERR("Failed to receive %#x\n", ret);
			goto err;
		}

		if (len >= sizeof(buf))
			len = sizeof(buf) - 1;
		buf[len] = '\0';

		ETLS_INFO("Client: %s\n", buf);


		/* Reply back to the client */
		ret = enclave_tls_transmit(handle, buf, &len);
		if (ret != ENCLAVE_TLS_ERR_NONE) {
			ETLS_ERR("Failed to transmit %#x\n", ret);
			goto err;
		}

		ocall_close(&ocall_ret, connd);
	}

	return 0;

err:
	/* Ignore the error code of cleanup in order to return the prepositional error */
	enclave_tls_cleanup(handle);
	return -1;
}

int ecall_etls_client_startup(sgx_enclave_id_t enclave_id,
                              enclave_tls_log_level_t log_level,
                              char *attester_type,
                              char *verifier_type,
                              char *tls_type,
                              char *crypto_type,
                              unsigned long flags,
                              uint32_t s_ip,
                              uint16_t s_port)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strncpy(conf.attester_type, attester_type, strlen(attester_type));
	strncpy(conf.verifier_type, verifier_type, strlen(verifier_type));
	strncpy(conf.tls_type, tls_type, strlen(tls_type));
	strncpy(conf.crypto_type, crypto_type, strlen(crypto_type));
	conf.enclave_id = enclave_id;
	conf.flags = flags;
	
	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol.
	 */
	int64_t sockfd;
	int sgx_status = ocall_socket(&sockfd,
                                      ETLS_AF_INET,
                                      ETLS_SOCK_STREAM,
                                      0);
	if (sgx_status != SGX_SUCCESS || sockfd < 0) {
		ETLS_ERR("Failed to call socket() %#x %d\n",
                         sgx_status, sockfd);
		return -1;
	}
	
	struct etls_sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = ETLS_AF_INET;
	s_addr.sin_addr.s_addr = s_ip;
	s_addr.sin_port = s_port;
	
	/* Connect to the server */
	int ocall_ret = 0;
	sgx_status = ocall_connect(&ocall_ret,
                                   sockfd,
                                   (struct etls_sockaddr *)&s_addr,
                                   sizeof(s_addr));
	if (sgx_status != SGX_SUCCESS || ocall_ret == -1) {
		ETLS_ERR("failed to call connect() %#x %d\n",
                          sgx_status, ocall_ret);
		return -1;
	}

	/* Enclave-tls init */
	libenclave_tls_init();	
	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Failed to initialize enclave tls %#x\n", ret);
		return -1;
	}
	
	ret = enclave_tls_negotiate(handle, (int)sockfd);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Failed to negotiate %#x\n", ret);
		goto err;
	}
	
	const char *msg = "Hello and welcome to Enclave TLS!\n";
	size_t len = strlen(msg);
	ret = enclave_tls_transmit(handle, (void *)msg, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strlen(msg)) {
		ETLS_ERR("Failed to transmit %#x\n", ret);
		goto err;
	}
	
	char buf[256];
	len = sizeof(buf);
	ret = enclave_tls_receive(handle, buf, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Failed to receive %#x\n", ret);
		goto err;
	}
	
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	buf[len] = '\0';
	
	/* Server running in SGX Enclave will send mrenclave, mrsigner and hello message to client */
	if (len >= 2 * sizeof(sgx_measurement_t)) {
		ETLS_INFO("Server's SGX identity:\n");
		ETLS_INFO("  . MRENCLAVE = ");
		for (int i = 0; i < 32; ++i)
			printf("%02x", (uint8_t)buf[i]);
		printf("\n");
		ETLS_INFO("  . MRSIGNER  = ");
		for (int i = 32; i < 64; ++i)
			printf("%02x", (uint8_t)buf[i]);
		printf("\n");
		
		memcpy(buf, buf + 2 * sizeof(sgx_measurement_t),
                       len - 2 * sizeof(sgx_measurement_t));
		buf[len - 2 * sizeof(sgx_measurement_t)] = '\0';
		
		ETLS_INFO("Server:\n%s\n", buf);
	} else {
	        /* Server not running in SGX Enlcave will only send hello message to client */
	        ETLS_INFO("Server: %s\n", buf);
	}
	
	/* Sanity check whether the response is expected */
	if (strcmp(msg, buf)) {
	        printf("Invalid response retrieved from enclave-tls server\n");
	        goto err;
	}
	
	ret = enclave_tls_cleanup(handle);
	if (ret != ENCLAVE_TLS_ERR_NONE)
	        ETLS_ERR("Failed to cleanup %#x\n", ret);
	
	return ret;

err:
        /* Ignore the error code of cleanup in order to return the prepositional error */
        enclave_tls_cleanup(handle);
        return -1;
}
