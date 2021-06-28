/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CORE_H
#define _INTERNAL_CORE_H

#include <sys/types.h>
#include <enclave-tls/attester.h>
#include <enclave-tls/verifier.h>
#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/api.h>
#ifdef SGX
#include "etls_syscalls.h"
#endif

typedef struct etls_core_context_t {
	enclave_tls_conf_t config;
	unsigned long flags;
	enclave_attester_ctx_t *attester;
	enclave_verifier_ctx_t *verifier;
	tls_wrapper_ctx_t *tls_wrapper;
	crypto_wrapper_ctx_t *crypto_wrapper;
} etls_core_context_t;

#ifdef SGX
typedef struct ocall_dirent etls_dirent;
#else
typedef struct dirent etls_dirent;
#endif

extern etls_core_context_t global_core_context;

extern enclave_tls_err_t etls_core_generate_certificate(etls_core_context_t *);

extern void etls_exit(void);

extern enclave_tls_log_level_t etls_loglevel_getenv(const char *name);

extern enclave_tls_err_t etls_instance_init(const char *type,
                                               const char *realpath,
                                               void **handle);

extern ssize_t etls_write(int fd, const void *buf, size_t count);

extern ssize_t etls_read(int fd, void *buf, size_t count);

extern uint64_t etls_opendir(const char* name);

extern int etls_readdir(uint64_t dirp, etls_dirent **ptr);

extern int etls_closedir(uint64_t dir);

// Whether the quote instance is initialized
#define ENCLAVE_TLS_CTX_FLAGS_QUOTING_INITIALIZED (1 << 0)
// Whether the tls lib is initialized
#define ENCLAVE_TLS_CTX_FLAGS_TLS_INITIALIZED (1 << 16)
// Whether the tls library has completed the creation and initialization of the TLS certificate
#define ENCLAVE_TLS_CTX_FLAGS_CERT_CREATED (1 << 17)
// Whether the crypto lib is initialized
#define ENCLAVE_TLS_CTX_FLAGS_CRYPTO_INITIALIZED (1 << 18)

#endif
