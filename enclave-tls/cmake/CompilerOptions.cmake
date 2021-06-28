# Normal and occlum mode
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -fPIC")
set(ENCLAVE_TLS_LDFLAGS "-fPIC -Bsymbolic -ldl")

if(OCCLUM)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOCCLUM")
endif()

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()

# SGX mode
if(SGX)
    if(SGX_HW)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else()
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
    endif()
    set(SGX_DACP_QL sgx_dcap_ql)
    set(SGX_DACP_QUOTEVERIFY sgx_dcap_quoteverify)
    set(SGX_DCAP_TVL sgx_dcap_tvl)
    
    set(APP_COMMON_FLAGS "-fPIC -Wno-attributes")
    
    if(SGX_DEBUG)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O0 -g")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(SGX_PRERELEASE)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O2")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DNDEBUG -DEDEBUG -UDEBUG")
    elseif(SGX_RELEASE)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O2")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DNDEBUG -UEDEBUG -UDEBUG")
    endif()

    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wall -Wextra -Winit-self")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wformat-security -Wmissing-include-dirs -Wfloat-equal")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wundef -Wshadow -Wcast-align -Wcast-qual -Wconversion")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wredundant-decls")

    set(ENCLAVE_COMMON_FLAGS "-nostdinc -ffreestanding -fvisibility=hidden -fpie -ffunction-sections -fdata-sections")
    
    if(CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
        set(ENCLAVE_COMMON_FLAGS "${ENCLAVE_COMMON_FLAGS} -fstack-protector")
    else()
        set(ENCLAVE_COMMON_FLAGS "${ENCLAVE_COMMON_FLAGS} -fstack-protector-strong")
    endif()
    
    set(SGX_COMMON_CFLAGS "${SGX_COMMON_FLAGS} -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants")
    set(SGX_COMMON_CXXFLAGS "${SGX_COMMON_FLAGS} -Wnon-virtual-dtor -std=c++11")
    
    set(ENCLAVE_INCLUDES "${SGX_INCLUDE}" "${SGX_TLIBC_INCLUDE}" "${SGX_LIBCXX_INCLUDE}" "/usr/include")
    set(ENCLAVE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} ${ENCLAVE_COMMON_FLAGS}")
    set(ENCLAVE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SGX_COMMON_CXXFLAGS} ${ENCLAVE_COMMON_FLAGS} -nostdinc++")
    
    set(APP_INCLUDES "${SGX_INCLUDE}")
    set(APP_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} ${APP_COMMON_FLAGS}")
    set(APP_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SGX_COMMON_CXXFLAGS} ${APP_COMMON_FLAGS}")
endif()

# Wolfssl
# Set wolfssl compile flags
set(WOLFSSL_CFLAGS "-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT")
set(WOLFSSL_CFLAGS "${WOLFSSL_CFLAGS} -Wno-stringop-truncation -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN")
set(WOLFSSL_CFLAGS "${WOLFSSL_CFLAGS} -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DKEEP_PEER_CERT")
set(WOLFSSL_CFLAGS "${WOLFSSL_CFLAGS} -DWOLFSSL_TEST_CERT -DWOLFSSL_SMALL_CERT_VERIFY")
if(SGX)
    set(WOLFSSL_SGX_CFLAGS "${APP_C_FLAGS} ${WOLFSSL_CFLAGS} -DUSER_TIME -DWOLFSSL_SGX -DFP_MAX_BITS=8192")
    set(ENCLAVE_C_FLAGS "${ENCLAVE_C_FLAGS} ${WOLFSSL_CFLAGS} -DUSER_TIME -DWOLFSSL_SGX -DFP_MAX_BITS=8192 -DWOLFSSL_SGX_WRAPPER")
    set(ENCLAVE_CXX_FLAGS "${ENCLAVE_C_FLAGS} ${WOLFSSL_CFLAGS} -DUSER_TIME -DWOLFSSL_SGX -DFP_MAX_BITS=8192 -DWOLFSSL_SGX_WRAPPER")
endif()

