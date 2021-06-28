# enclave_tls
set(ENCLAVE_TLS_INSTALL_PATH "/opt/enclave-tls")

# encalve_tls/lib
set(ENCLAVE_TLS_INSTALL_LIB_PATH "${ENCLAVE_TLS_INSTALL_PATH}/lib")

# enclave_tls/lib/crypto-wrappers
set(ENCLAVE_TLS_INSTALL_LIBCW_PATH "${ENCLAVE_TLS_INSTALL_PATH}/lib/crypto-wrappers")

# enclave_tls/lib/enclave-quotes
set(ENCLAVE_TLS_INSTALL_LIBEQ_PATH "${ENCLAVE_TLS_INSTALL_PATH}/lib/enclave-quotes")

# enclave_tls/lib/tls-wrappers
set(ENCLAVE_TLS_INSTALL_LIBTW_PATH "${ENCLAVE_TLS_INSTALL_PATH}/lib/tls-wrappers")

# enclave_tls/bin
set(ENCLAVE_TLS_INSTALL_BIN_PATH "${ENCLAVE_TLS_INSTALL_PATH}/bin")

# enclave_tls/include
set(ENCLAVE_TLS_INSTALL_INCLUDE_PATH "${ENCLAVE_TLS_INSTALL_PATH}/include")

# sgx sdk
if(EXISTS $ENV{SGX_SDK})
    set(SGXSDK_INSTALL_PATH "$ENV{SGX_SDK}")
else()
    set(SGXSDK_INSTALL_PATH "/opt/intel/sgxsdk")
endif()

# sgx sdk library
set(SGXSDK_INSTALL_LIB_PATH "${SGXSDK_INSTALL_PATH}/lib64")

# sgx sdk include
set(SGXSDK_INSTALL_INCLUDE_PATH "${SGXSDK_INSTALL_PATH}/include")
