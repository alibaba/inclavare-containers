# src/Makefile
#

Topdir ?= $(shell readlink -f ..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

ifdef SGX
  Enclave_Tls_Cflags += \
    -I$(Topdir)/samples/sgx-stub-enclave \
    -I/opt/intel/sgxsdk/include \
    -I$(Topdir)/build/include
  Enclave_Tls_Extra_Ldflags := \
    -L/opt/intel/sgxsgk/lib64 -lsgx_uae_service -lsgx_urts \
    -lsgx_dcap_ql -lsgx_dcap_quoteverify
endif

libenclave_tls := $(notdir $(Enclave_Tls_Lib))
crypto_wrappers := $(addsuffix .so,$(addprefix libcrypto_wrapper_,nullcrypto openssl))
tls_wrappers := $(addsuffix .so,$(addprefix libtls_wrapper_,nulltls openssl))
attesters := $(addsuffix .so,$(addprefix libattester_,nullattester))
verifiers := $(addsuffix .so,$(addprefix libverifier_,nullverifier))

ifdef OCCLUM
  Enclave_Tls_Cflags += -DOCCLUM
  attesters += $(addsuffix .so,$(addprefix libattester_,sgx-ecdsa))
  verifiers += $(addsuffix .so,$(addprefix libverifier_,sgx-ecdsa))
endif

ifdef SGX
  attesters += $(addsuffix .so,$(addprefix libattester_,sgx-ecdsa sgx-la))
  verifiers += $(addsuffix .so,$(addprefix libverifier_,sgx-ecdsa sgx-ecdsa-qve sgx-la))
endif

all: $(addprefix $(Build_Libdir)/,$(libenclave_tls) $(crypto_wrappers) $(tls_wrappers) $(attesters) $(verifiers))

this_dir := $(shell pwd)
libenclave_tls_files := \
  $(wildcard \
    $(this_dir)/core/*.c $(this_dir)/api/*.c \
    $(this_dir)/crypto_wrappers/internal/*.c $(this_dir)/crypto_wrappers/api/*.c \
    $(this_dir)/tls_wrappers/internal/*.c $(this_dir)/tls_wrappers/api/*.c \
    $(this_dir)/attesters/internal/*.c $(this_dir)/attesters/api/*.c \
    $(this_dir)/verifiers/internal/*.c $(this_dir)/verifiers/api/*.c \
    $(this_dir)/util/sgxutils.c \
  )

ocall_files := \
  $(this_dir)/sgx/ocalls.c \
  $(this_dir)/attesters/sgx-ecdsa/ocalls.c \
  $(this_dir)/verifiers/sgx-ecdsa/ocalls.c \
  $(this_dir)/verifiers/sgx-ecdsa-qve/ocalls.c
ocall_objs := $(patsubst %c,%o,$(ocall_files))
ifdef SGX
  libenclave_tls_files += $(ocall_files)
endif

libenclave_tls_objs := $(libenclave_tls_files:.c=.o) util/toml.o
$(Build_Libdir)/$(libenclave_tls): $(Build_Dependencies) $(libenclave_tls_objs)
	@$(INSTALL) -d -m 0755 $(dir $@)
	$(LD) $(Enclave_Tls_Ldflags) -soname=$(notdir $@).$(Major_Version) -o $@ $(libenclave_tls_objs) -ldl -lc $(Enclave_Tls_Extra_Ldflags)

$(libenclave_tls_objs): %.o: %.c
	$(CC) -c $(Enclave_Tls_Cflags) -o $@ $<

$(addprefix $(Build_Libdir)/,$(crypto_wrappers) $(tls_wrappers)):
	@n=$(patsubst lib%.so,%,$(notdir $@)); \
	dir=`echo $$n | cut -d '_' -f1-2`; \
	name=$${n#$${dir}_}; \
	make -C $(this_dir)/$${dir}s/$$name

$(addprefix $(Build_Libdir)/,$(attesters) $(verifiers)):
	@n=$(patsubst lib%.so,%,$(notdir $@)); \
	dir=`echo $$n | cut -d '_' -f1`; \
	name=$${n#$${dir}_}; \
	make -C $(this_dir)/$${dir}s/$$name

util/toml.o: util/toml.c util/toml.h
	$(CC) -fPIC -o $@ -c $<

toml_h_uri ?= \
	https://raw.githubusercontent.com/cktan/tomlc99/master/toml.h

toml_c_uri ?= \
	https://raw.githubusercontent.com/cktan/tomlc99/master/toml.c

util/toml.c:
	if [ ! -e "util/toml.c" ]; then \
		wget $(toml_c_uri) -P util/; \
	fi

util/toml.h:
	if [ ! -e "util/toml.h" ]; then \
		wget $(toml_h_uri) -P util/; \
		cp util/toml.h ./include/enclave-tls/; \
	fi

install_libenclave_tls: $(Build_Libdir)/$(libenclave_tls)
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)
	dest=$(libenclave_tls).$(Major_Version).$(Minor_Version).$(Patch_Version); \
	$(INSTALL) -m 0755 $< $(Enclave_Tls_Libdir)/$$dest && \
	ln -sf $$dest $(Enclave_Tls_Libdir)/$(libenclave_tls).$(Major_Version) && \
	ln -sf $$dest $(Enclave_Tls_Libdir)/$(libenclave_tls)

install: all
	make install_libenclave_tls
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Root)/include/enclave-tls
	$(INSTALL) -m 0444 $(Enclave_Tls_Incdir)/enclave-tls/* $(Enclave_Tls_Root)/include/enclave-tls
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/crypto-wrappers
	$(INSTALL) -m 0755 $(Build_Libdir)/crypto-wrappers/libcrypto_wrapper_* \
	  $(Enclave_Tls_Libdir)/crypto-wrappers
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/tls-wrappers
	$(INSTALL) -m 0755 $(Build_Libdir)/tls-wrappers/libtls_wrapper_* \
	  $(Enclave_Tls_Libdir)/tls-wrappers
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/attesters
	$(INSTALL) -m 0755 $(Build_Libdir)/attesters/libattester_* \
	  $(Enclave_Tls_Libdir)/attesters
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/verifiers
	$(INSTALL) -m 0755 $(Build_Libdir)/verifiers/libverifier_* \
	  $(Enclave_Tls_Libdir)/verifiers

uninstall:
	@rm -rf $(Enclave_Tls_Root)

Cleans += $(Build_Libdir) $(libenclave_tls_objs) $(ocall_objs)
Clean_Dirs += crypto_wrappers tls_wrappers attesters verifiers

Extra_Phonies += install_libenclave_tls

include $(Topdir)/rules/build_rules.mk
