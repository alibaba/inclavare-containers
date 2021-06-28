/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

extern tls_wrapper_err_t nulltls_pre_init(void);
extern tls_wrapper_err_t nulltls_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t nulltls_use_privkey(tls_wrapper_ctx_t *ctx, void *privkey_buf,
					     size_t privkey_len);
extern tls_wrapper_err_t nulltls_use_cert(tls_wrapper_ctx_t *ctx,
					  enclave_tls_cert_info_t *cert_info);
extern tls_wrapper_err_t nulltls_negotiate(tls_wrapper_ctx_t *, int fd);
extern tls_wrapper_err_t nulltls_transmit(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t nulltls_receive(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t nulltls_cleanup(tls_wrapper_ctx_t *);

static tls_wrapper_opts_t nulltls_opts = {
	.api_version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.name = "nulltls",
	.priority = 0,
	.pre_init = nulltls_pre_init,
	.init = nulltls_init,
	.use_privkey = nulltls_use_privkey,
	.use_cert = nulltls_use_cert,
	.negotiate = nulltls_negotiate,
	.transmit = nulltls_transmit,
	.receive = nulltls_receive,
	.cleanup = nulltls_cleanup,
};

#ifdef SGX
void libtls_wrapper_nulltls_init(void)
#else
void __attribute__((constructor)) libtls_wrapper_nulltls_init(void)
#endif
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&nulltls_opts);
	if (err != TLS_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the tls wrapper 'nulltls' %#x\n", err);
}
