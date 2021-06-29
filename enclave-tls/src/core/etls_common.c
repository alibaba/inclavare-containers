#include <stdlib.h>
#ifndef SGX
#include <dlfcn.h>
#include <strings.h>
#include <dirent.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "enclave-tls/api.h"
#include "enclave-tls/log.h"
#include "internal/core.h"
#include "err.h"

#ifdef SGX
#include "etls_t.h"

extern void libcrypto_wrapper_nullcrypto_init(void);
extern void libcrypto_wrapper_wolfcrypt_init(void);
extern void libattester_null_init(void);
extern void libverifier_null_init(void);
extern void libattester_sgx_ecdsa_init(void);
extern void libverifier_sgx_ecdsa_init(void);
extern void libverifier_sgx_ecdsa_qve_init(void);
extern void libattester_sgx_la_init(void);
extern void libverifier_sgx_la_init(void);
extern void libtls_wrapper_nulltls_init(void);
extern void libtls_wrapper_wolfssl_init(void);
#endif

void etls_exit(void)
{
#ifndef SGX
	exit(EXIT_FAILURE);
#else
	ocall_exit();
#endif
}

enclave_tls_log_level_t etls_loglevel_getenv(const char *name)
{
	char *log_level_str = NULL;
#ifdef SGX
	size_t log_level_len = 32;
	log_level_str = calloc(1, log_level_len);
	memset(log_level_str, 0, log_level_len);
	ocall_getenv(name, log_level_str, log_level_len);
#else
	log_level_str = getenv(name);
#endif
	if (log_level_str) {
#ifdef SGX
		if (!strcmp(log_level_str, "debug") || !strcmp(log_level_str, "DEBUG"))
#else
		if (!strcasecmp(log_level_str, "debug"))
#endif
			return ENCLAVE_TLS_LOG_LEVEL_DEBUG;
#ifdef SGX
		else if (!strcmp(log_level_str, "info") || !strcmp(log_level_str, "INFO"))
#else
		else if (!strcasecmp(log_level_str, "info"))
#endif
			return ENCLAVE_TLS_LOG_LEVEL_INFO;
#ifdef SGX
		else if (!strcmp(log_level_str, "warn") || !strcmp(log_level_str, "WARN"))
#else
		else if (!strcasecmp(log_level_str, "warn"))
#endif
			return ENCLAVE_TLS_LOG_LEVEL_WARN;
#ifdef SGX
		else if (!strcmp(log_level_str, "error") || !strcmp(log_level_str, "ERROR"))
#else
		else if (!strcasecmp(log_level_str, "error"))
#endif
			return ENCLAVE_TLS_LOG_LEVEL_ERROR;
#ifdef SGX
		else if (!strcmp(log_level_str, "fatal") || !strcmp(log_level_str, "FATAL"))
#else
		else if (!strcasecmp(log_level_str, "fatal"))
#endif
			return ENCLAVE_TLS_LOG_LEVEL_FATAL;
#ifdef SGX
		else if (!strcmp(log_level_str, "off") || !strcmp(log_level_str, "OFF"))
#else
		else if (!strcasecmp(log_level_str, "off"))
#endif
			return ENCLAVE_TLS_LOG_LEVEL_NONE;
	}

	return ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
}

enclave_tls_err_t etls_instance_init(const char *name,
                                     __attribute__((unused)) const char *realpath,
                                     __attribute__((unused)) void **handle
                                     )
{
#ifdef SGX
	if (!strcmp(name, "nullcrypto"))
		libcrypto_wrapper_nullcrypto_init();
	else if (!strcmp(name, "wolfcrypt"))
		libcrypto_wrapper_wolfcrypt_init();
	else if (!strcmp(name, "nullattester"))
		libattester_null_init();
	else if (!strcmp(name, "nullverifier"))
		libverifier_null_init();
	else if (!strcmp(name, "sgx_ecdsa")) {
		libattester_sgx_ecdsa_init();
		libverifier_sgx_ecdsa_init();
        }
	else if (!strcmp(name, "sgx_ecdsa_qve"))
		libverifier_sgx_ecdsa_qve_init();
	else if (!strcmp(name, "sgx_la")) {
                libattester_sgx_la_init();
		libverifier_sgx_la_init();
        }
	else if (!strcmp(name, "nulltls"))
		libtls_wrapper_nulltls_init();
	else if (!strcmp(name, "wolfssl"))
		libtls_wrapper_wolfssl_init();
	else
		return ENCLAVE_TLS_ERR_NO_NAME;
#else
	*handle = dlopen(realpath, RTLD_LAZY);
	if (*handle == NULL) {
		ETLS_ERR("failed on dlopen(): %s\n", dlerror());
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}
#endif

	return ENCLAVE_TLS_ERR_NONE;
}

ssize_t etls_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;
#ifdef SGX
	int sgx_status = ocall_write(&rc, fd, buf, count);
	if (SGX_SUCCESS != sgx_status) {
		ETLS_ERR("sgx failed to write data, sgx status: 0x%04x\n", sgx_status);
	}
#else
	rc = write(fd, buf, count);
#endif

	return rc;
}

ssize_t etls_read(int fd, void *buf, size_t count)
{
	ssize_t rc;
#ifdef SGX
	int sgx_status = ocall_read(&rc, fd, buf, count);
	if (SGX_SUCCESS != sgx_status) {
		ETLS_ERR("sgx failed to read data, sgx status: 0x%04x\n", sgx_status);
	}
#else
	rc = read(fd, buf, count);
#endif
	return rc;
}

uint64_t etls_opendir(const char* name)
{
	uint64_t dir;
#ifdef SGX
	int sgx_status = ocall_opendir(&dir, name);
	if (sgx_status != SGX_SUCCESS) {
		ETLS_ERR("sgx failed to open %s, sgx status: 0x%04x\n", name, sgx_status);
	}
#else
	dir = (uint64_t)opendir(name);
#endif
	return dir;
}

int etls_readdir(uint64_t dirp, etls_dirent **ptr)
{
	int ret = 0;
#ifdef SGX
	*ptr = (etls_dirent *)calloc(1, sizeof(etls_dirent));
	ocall_readdir(&ret, dirp, *ptr);
#else
	*ptr = readdir((DIR*)dirp);
	if (*ptr == NULL)
		ret = 1;
#endif
	return ret;
}

int etls_closedir(uint64_t dir)
{
#ifdef SGX
	int ret = 0;
	ocall_closedir(&ret, dir);
	return ret;
#else
	return closedir((DIR*)dir);
#endif
}
