/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include "internal/core.h"
#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/crypto_wrapper.h"
#ifdef SGX
#include "etls_t.h"
#endif

/* The global configurations present by /opt/enclave-tls/config.toml */
etls_core_context_t global_core_context;
/* The global log level used by log.h */
enclave_tls_log_level_t global_log_level = ENCLAVE_TLS_LOG_LEVEL_DEFAULT;

#ifdef SGX
void libenclave_tls_init(void)
#else
void __attribute__((constructor)) libenclave_tls_init(void)
#endif
{
	ETLS_DEBUG("called\n");

	global_log_level = etls_loglevel_getenv("ENCLAVE_TLS_GLOBAL_LOG_LEVEL");	

	/* Initialize global configurations. It is intend to leave tls_type,
	 * attester_type, verifier_type and crypto_type empty to take the
	 * best guess.
	 */
	// clang-format off
	global_core_context.config.api_version = ENCLAVE_TLS_API_VERSION_DEFAULT;
	// clang-format on
	global_core_context.config.log_level = global_log_level;
	global_core_context.config.cert_algo = ENCLAVE_TLS_CERT_ALGO_DEFAULT;

	/* TODO: load and parse the global configuration file */

	/* Load all crypto wrapper instances */
	enclave_tls_err_t err = etls_crypto_wrapper_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE) {
		ETLS_FATAL("failed to load any crypto wrapper %#x\n", err);
		etls_exit();
	}

	/* Load all enclave attester instances */
	err = etls_enclave_attester_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE) {
		ETLS_FATAL("failed to load any enclave attester %#x\n", err);
		etls_exit();
	}
	/* Load all enclave verifier instances */
	err = etls_enclave_verifier_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE) {
		ETLS_FATAL("failed to load any enclave verifier %#x\n", err);
		etls_exit();
	}

	/* Load all tls wrapper instances */
	err = etls_tls_wrapper_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE) {
		ETLS_FATAL("failed to load any tls wrapper %#x\n", err);
		etls_exit();
	}
}
