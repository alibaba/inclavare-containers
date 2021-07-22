/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>
#include <enclave-tls/toml.h>

#define DEFAULT_PORT	    1234
#define DEFAULT_IP	    "127.0.0.1"
#define ENCLAVE_CONFIG_TOML "/opt/enclave-tls/config.toml"

// clang-format off
#ifdef OCCLUM
  #include <sgx_report.h>
#elif defined(SGX)
  #include <sgx_urts.h>
  #include <sgx_quote.h>

#define ENCLAVE_FILENAME        "sgx_stub_enclave.signed.so"

static sgx_enclave_id_t load_enclave(bool debug_enclave)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_enclave, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		ETLS_ERR("Failed to load enclave %d\n", ret);
		return -1;
	}

	ETLS_DEBUG("Success to load enclave id %ld\n", eid);

	return eid;
}
#endif
// clang-format on

static uint8_t user_mrsigner[32];
static uint8_t user_mrenclave[32];

static int parse_hex(const char *hex, void *buffer, size_t buffer_size)
{
	if (!hex || !buffer || buffer_size == 0)
		return -1;

	if (strlen(hex) != buffer_size * 2) {
		ETLS_ERR("Invalid hex string (%s) length\n", hex);
		return -1;
	}

	for (size_t i = 0; i < buffer_size; i++) {
		if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1])) {
			ETLS_ERR("Invalid hex string '%s'\n", hex);
			return -1;
		}

		sscanf(hex + i * 2, "%02hhx", &((uint8_t *)buffer)[i]);
	}

	return 0;
}

static int parse_config_file(char *path)
{
	FILE *fp;
	char errbuf[200];

	fp = fopen(path, "r");
	if (!fp) {
		ETLS_ERR("failed to open /opt/enclave-tls/config.toml\n");
		goto err;
	}

	toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
	fclose(fp);

	if (!conf) {
		ETLS_ERR("failed to parse %s\n", errbuf);
		goto err;
	}
	toml_table_t *enclave_info = toml_table_in(conf, "enclave-info");
	if (!enclave_info) {
		ETLS_DEBUG("there is no enclave-info data\n");
		return 0;
	}

	toml_datum_t mrsigner = toml_string_in(enclave_info, "mrsigner");
	if (mrsigner.ok) {
		if (parse_hex(mrsigner.u.s, user_mrsigner, sizeof(user_mrsigner)))
			return -1;
	} else
		ETLS_DEBUG("there is no mrsigner\n");

	toml_datum_t mrenclave = toml_string_in(enclave_info, "mrenclave");
	if (mrenclave.ok) {
		if (parse_hex(mrenclave.u.s, user_mrenclave, sizeof(user_mrenclave)))
			return -1;
	} else
		ETLS_DEBUG("there is no mrenclave\n");

	free(mrsigner.u.s);
	free(mrenclave.u.s);
	toml_free(conf);

	return 0;
err:
	return -1;
}

int enclave_tls_echo(int fd, enclave_tls_log_level_t log_level, char *attester_type,
		     char *verifier_type, char *tls_type, char *crypto_type, bool mutual,
		     bool debug_enclave)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto_type);
#ifdef SGX
	conf.enclave_id = load_enclave(debug_enclave);
	if (conf.enclave_id == -1) {
		ETLS_ERR("Failed to load sgx stub enclave\n");
		return -1;
	}
#endif
	if (mutual)
		conf.flags |= ENCLAVE_TLS_CONF_FLAGS_MUTUAL;

	if (!parse_config_file(ENCLAVE_CONFIG_TOML)) {
		memcpy(conf.enclave_info.mrsigner, user_mrsigner, sizeof(user_mrsigner));
		memcpy(conf.enclave_info.mrenclave, user_mrenclave, sizeof(user_mrenclave));
	}

	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Failed to initialize enclave tls %#x\n", ret);
		return -1;
	}

	ret = enclave_tls_negotiate(handle, fd);
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

#if defined(OCCLUM) || defined(SGX)
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
	} else
#endif
	{
		/* Server not running in SGX Enlcave will only send hello message to client */
		ETLS_INFO("Server: %s\n", buf);
	}

	/* Sanity check whether the response is expected */
	if (strcmp(msg, buf)) {
		ETLS_ERR("Invalid response retrieved from enclave-tls server\n");
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

int main(int argc, char **argv)
{
	printf("    - Welcome to Enclave-TLS sample client program\n");

	char *const short_options = "a:v:t:c:ml:i:p:P:h";
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
		{ "product-enclave", no_argument, NULL, 'P' },
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
	char *srv_ip = DEFAULT_IP;
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
			srv_ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'P':
			debug_enclave = false;
			break;
		case -1:
			break;
		case 'h':
			puts("    Usage:\n\n"
			     "        enclave-tls-client <options> [arguments]\n\n"
			     "    Options:\n\n"
			     "        --attester/-a value   set the type of quote attester\n"
			     "        --verifier/-v value   set the type of quote verifier\n"
			     "        --tls/-t value        set the type of tls wrapper\n"
			     "        --crypto/-c value     set the type of crypto wrapper\n"
			     "        --mutual/-m           set to enable mutual attestation\n"
			     "        --log-level/-l        set the log level\n"
			     "        --ip/-i               set the listening ip address\n"
			     "        --port/-p             set the listening tcp port\n"
			     "        --product-enclave/-P  set to enable product enclave\n"
			     "        --help/-h             show the usage\n");
		default:
			exit(1);
		}
	} while (opt != -1);

	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol.
	 */

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("failed to call socket()\n");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(port);

	/* Get the server IPv4 address from the command line call */
	if (inet_pton(AF_INET, srv_ip, &s_addr.sin_addr) != 1) {
		ETLS_ERR("invalid server address\n");
		return -1;
	}

	/* Connect to the server */
	if (connect(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
		perror("failed to call connect()\n");
		return -1;
	}

	return enclave_tls_echo(sockfd, log_level, attester_type, verifier_type, tls_type,
				crypto_type, mutual, debug_enclave);
}
