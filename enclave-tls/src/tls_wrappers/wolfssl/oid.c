/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdlib.h>

#define OID(N)                                                                  \
	{                                                                       \
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N) \
	}

const uint8_t ias_response_body_oid[] = OID(0x02);
const uint8_t ias_root_cert_oid[] = OID(0x03);
const uint8_t ias_leaf_cert_oid[] = OID(0x04);
const uint8_t ias_report_signature_oid[] = OID(0x05);

const uint8_t ecdsa_quote_oid[] = OID(0x06);
const uint8_t pck_crt_oid[] = OID(0x07);
const uint8_t pck_sign_chain_oid[] = OID(0x08);
const uint8_t tcb_info_oid[] = OID(0x09);
const uint8_t tcb_sign_chain_oid[] = OID(0x0a);
const uint8_t qe_identity_oid[] = OID(0x0b);
const uint8_t root_ca_crl_oid[] = OID(0x0c);
const uint8_t pck_crl_oid[] = OID(0x0d);
const uint8_t la_report_oid[] = OID(0x0e);

const size_t ias_oid_len = sizeof(ias_response_body_oid);
