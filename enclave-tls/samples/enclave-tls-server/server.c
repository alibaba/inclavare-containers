/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#define DEFAULT_PORT 1234
#define DEFAULT_IP   "127.0.0.1"

// clang-format off
#ifdef OCCLUM
  #include <sgx_report.h>
  #include <fcntl.h>
  #include <sys/ioctl.h>
#elif defined(SGX)
  #include <sgx_urts.h>
  #include <sgx_quote.h>
  #include "sgx_stub_u.h"

  #define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"

static sgx_enclave_id_t load_enclave(bool debug_enclave)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_enclave, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to load enclave %d\n", ret);
		return -1;
	}

	printf("Success to load enclave id %ld\n", eid);

	return eid;
}
#endif

#ifdef OCCLUM
typedef struct {
	const sgx_target_info_t *target_info;
	const sgx_report_data_t *report_data;
	sgx_report_t *report;
} sgxioc_create_report_arg_t;

  #define SGXIOC_SELF_TARGET   _IOR('s', 3, sgx_target_info_t)
  #define SGXIOC_CREATE_REPORT _IOWR('s', 4, sgxioc_create_report_arg_t)
  #define ENCLAVE_TLS_HELLO    "Hello and welcome to Enclave TLS!\n"

static int sgx_create_report(sgx_report_t *report)
{
	int sgx_fd = open("/dev/sgx", O_RDONLY);

	if (sgx_fd < 0) {
		ETLS_ERR("Failed to open sgx device\n");
		return -1;
	}

	sgx_target_info_t target_info;
	if (ioctl(sgx_fd, SGXIOC_SELF_TARGET, &target_info) < 0) {
		close(sgx_fd);
		ETLS_ERR("Failed to ioctl get quote and returned errno %s\n", strerror(errno));
		return -1;
	}

	sgxioc_create_report_arg_t arg;
	arg.target_info = &target_info;
	arg.report_data = NULL;
	arg.report = report;
	if (ioctl(sgx_fd, SGXIOC_CREATE_REPORT, &arg) < 0) {
		close(sgx_fd);
		ETLS_ERR("Failed to ioctl get report and return error %s\n", strerror(errno));
		return -1;
	}

	close(sgx_fd);

	return 0;
}
#endif
// clang-format on

#ifdef SGX
int enclave_tls_server_startup(enclave_tls_log_level_t log_level, char *attester_type,
			       char *verifier_type, char *tls_type, char *crypto_type,
                               bool mutual, bool debug_enclave, char *ip, int port)
{
	unsigned long long enclave_id = 0;
	unsigned long flags = 0;
	uint32_t s_ip = inet_addr(ip);
	uint16_t s_port = htons(port);

	enclave_id = load_enclave(debug_enclave);
	if (enclave_id == -1) {
		printf("Failed to load sgx stub enclave\n");
		return -1;
	}

	flags |= ENCLAVE_TLS_CONF_FLAGS_SERVER;
	if (mutual)
		flags |= ENCLAVE_TLS_CONF_FLAGS_MUTUAL;

	int ret = 0;
	int sgx_status = ecall_etls_server_startup(enclave_id, &ret, enclave_id,
                                                   log_level, attester_type,
                                                   verifier_type, tls_type,
                                                   crypto_type, flags,
                                                   s_ip, s_port);

	return ret;
}
#else
int enclave_tls_server_startup(enclave_tls_log_level_t log_level, char *attester_type,
                               char *verifier_type, char *tls_type, char *crypto_type,
                               bool mutual, bool debug_enclave, char *ip, int port)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto_type);
	conf.flags |= ENCLAVE_TLS_CONF_FLAGS_SERVER;
	if (mutual)
		conf.flags |= ENCLAVE_TLS_CONF_FLAGS_MUTUAL;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Failed to call socket()");
		return -1;
	}

	int reuse = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuse, sizeof(int)) < 0) {
		perror("Failed to call setsockopt()");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_addr.s_addr = inet_addr(ip);
	s_addr.sin_port = htons(port);

	/* Bind the server socket */
	if (bind(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
		perror("Failed to call bind()");
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		perror("Failed to call listen()");
		return -1;
	}

	enclave_tls_handle handle;
	enclave_tls_err_t ret;
	ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Failed to initialize enclave tls %#x\n", ret);
		return -1;
	}

	/* Accept client connections */
	struct sockaddr_in c_addr;
	socklen_t size = sizeof(c_addr);
	while (1) {
		ETLS_INFO("Waiting for a connection ...\n");

		int connd = accept(sockfd, (struct sockaddr *)&c_addr, &size);
		if (connd < 0) {
			perror("Failed to call accept()");
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

#ifdef OCCLUM
		sgx_report_t app_report;
		if (sgx_create_report(&app_report) < 0) {
			ETLS_ERR("Failed to generate local report\n");
			goto err;
		}

		/* Write mrencalve, mesigner and hello into buff */
		memset(buf, 0, sizeof(buf));
		memcpy(buf, &app_report.body.mr_enclave, sizeof(sgx_measurement_t));
		memcpy(buf + sizeof(sgx_measurement_t), &app_report.body.mr_signer,
		       sizeof(sgx_measurement_t));
		memcpy(buf + 2 * sizeof(sgx_measurement_t), ENCLAVE_TLS_HELLO,
		       sizeof(ENCLAVE_TLS_HELLO));

		len = 2 * sizeof(sgx_measurement_t) + strlen(ENCLAVE_TLS_HELLO);
#endif

		/* Reply back to the client */
		ret = enclave_tls_transmit(handle, buf, &len);
		if (ret != ENCLAVE_TLS_ERR_NONE) {
			ETLS_ERR("Failed to transmit %#x\n", ret);
			goto err;
		}

		close(connd);
	}

	return 0;

err:
	/* Ignore the error code of cleanup in order to return the prepositional error */
	enclave_tls_cleanup(handle);
	return -1;
}
#endif

int main(int argc, char **argv)
{
	printf("    - Welcome to Enclave-TLS sample server program\n");

	char *const short_options = "a:v:t:c:ml:i:p:D:h";
	// clang-format off
	struct option long_options[] = {
		{ "attester", required_argument, NULL, 'a' },
		{ "verifier", required_argument, NULL, 'v' },
		{ "tls", required_argument, NULL, 't' },
		{ "crypto", required_argument, NULL, 'c' },
		{ "mutual", no_argument, NULL, 'm' },
		{ "log-level", required_argument, NULL, 'l' },
		{ "ip", required_argument, NULL, 'i' },
		{ "port", required_argument, NULL, 'p' },
		{ "debug-enclave", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	// clang-format on

	char *attester_type = "";
	char *verifier_type = "";
	char *tls_type = "";
	char *crypto_type = "";
	bool mutual = false;
	enclave_tls_log_level_t log_level = ENCLAVE_TLS_LOG_LEVEL_INFO;
	char *ip = DEFAULT_IP;
	int port = DEFAULT_PORT;
	bool debug_enclave = true;
	int opt;

	do {
		opt = getopt_long(argc, argv, short_options, long_options, NULL);
		switch (opt) {
		case 'a':
			attester_type = optarg;
			break;
		case 'v':
			verifier_type = optarg;
			break;
		case 't':
			tls_type = optarg;
			break;
		case 'c':
			crypto_type = optarg;
			break;
		case 'm':
			mutual = true;
			break;
		case 'l':
			if (!strcasecmp(optarg, "debug"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_DEBUG;
			else if (!strcasecmp(optarg, "info"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_INFO;
			else if (!strcasecmp(optarg, "warn"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_WARN;
			else if (!strcasecmp(optarg, "error"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_ERROR;
			else if (!strcasecmp(optarg, "fatal"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_FATAL;
			else if (!strcasecmp(optarg, "off"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_NONE;
			break;
		case 'i':
			ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'D':
			debug_enclave = true;
			break;
		case -1:
			break;
		case 'h':
			puts("    Usage:\n\n"
			     "        enclave-tls-server <options> [arguments]\n\n"
			     "    Options:\n\n"
			     "        --attester/-a value   set the type of quote attester\n"
			     "        --verifier/-v value   set the type of quote verifier\n"
			     "        --tls/-t value        set the type of tls wrapper\n"
			     "        --crypto/-c value     set the type of crypto wrapper\n"
			     "        --mutual/-m           set to enable mutual attestation\n"
			     "        --log-level/-l        set the log level\n"
			     "        --ip/-i               set the listening ip address\n"
			     "        --port/-p             set the listening tcp port\n"
			     "        --debug-enclave/-D    set to enable enclave debugging\n"
			     "        --help/-h             show the usage\n");
		default:
			exit(1);
		}
	} while (opt != -1);

	return enclave_tls_server_startup(log_level, attester_type, verifier_type, tls_type,
					  crypto_type, mutual, debug_enclave, ip, port);
}
