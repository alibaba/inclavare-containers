/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WOLFSSL_PRIVATE_H
#define _WOLFSSL_PRIVATE_H

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/signature.h>

typedef struct {
	WOLFSSL_CTX *ws;
	WOLFSSL *ssl;
} wolfssl_ctx_t;

extern const uint8_t ias_response_body_oid[];
extern const uint8_t ias_root_cert_oid[];
extern const uint8_t ias_leaf_cert_oid[];
extern const uint8_t ias_report_signature_oid[];

extern const uint8_t ecdsa_quote_oid[];
extern const uint8_t pck_crt_oid[];
extern const uint8_t pck_sign_chain_oid[];
extern const uint8_t tcb_info_oid[];
extern const uint8_t tcb_sign_chain_oid[];

extern const size_t ias_oid_len;
extern const uint8_t la_report_oid[];

static inline void print_wolfssl_err(WOLFSSL *ssl)
{
	char buf[128];
	int err = wolfSSL_get_error(ssl, 0);
	wolfSSL_ERR_error_string((unsigned long)err, buf);

	ETLS_DEBUG("%s (err = %d)\n", buf, err);
}

#endif
