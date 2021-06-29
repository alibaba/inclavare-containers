# src/external/wolfssl/Makefile
#

Topdir ?= $(shell readlink -f ../../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

ifneq ($(__Wolfssl_Env_Imported),1)
  include $(Topdir)/rules/wolfssl_env.mk
endif

# Note: we don't need to include sgx_env.mk here because the remaining
# necessary options

all: $(Build_Libdir)/libwolfssl.so $(Build_Libdir)/libwolfssl_sgx.a

SGX_LVI_MITIGATION ?= 1
SGX_SDK ?= /opt/intel/sgxsdk

ifeq ($(SGX_LVI_MITIGATION),1)
  include $(SGX_SDK)/buildenv.mk
  Wolfssl_Sgx_Cflags += $(MITIGATION_CFLAGS)
  Wolfssl_Sgx_Ldflags += $(MITIGATION_LDFLAGS)
endif

this_dir := $(shell pwd)
wolfssl_srcdir := $(this_dir)/wolfssl
$(Build_Libdir)/libwolfssl.so: $(wolfssl_srcdir)/src/.libs/libwolfssl.so
	make -C $(wolfssl_srcdir) install

$(wolfssl_srcdir)/src/.libs/libwolfssl.so: $(wolfssl_srcdir)
	make -C $(wolfssl_srcdir)

# Ideally, libwolfssl_sgx.a and libwolfssl.so could be built
# in parallel. Does not work however. Hence, the dependency forces a
# serial build.
#
# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
$(wolfssl_srcdir)/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a: $(Build_Libdir)/libwolfssl.so
	cd $(wolfssl_srcdir)/IDE/LINUX-SGX && \
	make -f sgx_t_static.mk CFLAGS="$(Wolfssl_Sgx_Cflags)" LDFLAGS="$(Wolfssl_Sgx_Ldflags)"

wolfssl_config_flags := \
  --prefix=$(shell readlink -f $(Build_Dir)) \
  --enable-writedup --enable-shared --enable-static --enable-keygen --enable-certgen \
  --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni \
  --enable-tlsv10
ifeq ($(Debug),1)
  wolfssl_config_flags += --enable-debug
endif

$(wolfssl_srcdir):
	if [ ! -d "$(wolfssl_srcdir)" ]; then \
	  cd `dirname $(wolfssl_srcdir)` && \
	  git clone -b v4.6.0-stable https://github.com/wolfSSL/wolfssl && \
	  cd wolfssl && git apply --reject $(this_dir)/patch/wolfssl.patch && \
	  ./autogen.sh && \
	  CFLAGS="$(Wolfssl_Cflags)" LDFLAGS="$(Wolfssl_Ldflags)" ./configure $(wolfssl_config_flags); \
	fi

$(Build_Libdir)/libwolfssl_sgx.a: $(wolfssl_srcdir)/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a
	$(INSTALL) -d -m 0755 $(dir $@)
	$(INSTALL) -m 0755 $< $@

config:
	if [ -d "$(wolfssl_srcdir)" ]; then \
	  cd "$(wolfssl_srcdir)" && \
	  CFLAGS="$(Wolfssl_Cflags)" LDFLAGS="$(Wolfssl_Ldflags)" ./configure $(wolfssl_config_flags); \
	fi

clean:
	@rm -f $(Build_Libdir)/libwolfssl*

install: all
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)
	$(INSTALL) -m 0755 $(Build_Libdir)/libwolfssl* $(Enclave_Tls_Libdir)

uninstall:
	@rm -rf "$(Enclave_Tls_Libdir)"/libwolfssl*
	@rm -rf "$(Enclave_Tls_Incdir)/wolfssl"

mrproper:
	@rm -rf $(wolfssl_srcdir)

# TODO
#ifneq ($(__Build_Rules_Imported),1)
#  include $(Topdir)/rules/build_rules.mk
#endif
