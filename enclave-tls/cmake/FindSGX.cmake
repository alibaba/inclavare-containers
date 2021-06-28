include(FindPackageHandleStandardArgs)

if(EXISTS SGX_DIR)
    set(SGX_PATH ${SGX_DIR})
elseif(EXISTS SGX_ROOT)
    set(SGX_PATH ${SGX_ROOT})
elseif(EXISTS $ENV{SGX_SDK})
    set(SGX_PATH $ENV{SGX_SDK})
elseif(EXISTS $ENV{SGX_DIR})
    set(SGX_PATH $ENV{SGX_DIR})
elseif(EXISTS $ENV{SGX_ROOT})
    set(SGX_PATH $ENV{SGX_ROOT})
else()
    set(SGX_PATH "/opt/intel/sgxsdk")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SGX_COMMON_FLAGS -m32)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib32)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x86/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x86/sgx_edger8r)
else()
    set(SGX_COMMON_FLAGS -m64)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib64)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x64/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x64/sgx_edger8r)
endif()
set(SGX_INCLUDE_PATH ${SGX_PATH}/include)

# Look for the header file
find_path(SGX_INCLUDE NAMES sgx.h PATHS ${SGX_INCLUDE_PATH})

# Look for the library
find_library(SGX_LIBRARY_DIR NAMES sgx_urts PATHS ${SGX_LIBRARY_PATH})

# Handle the QUIETLY and REQUIRED arguments and set ENCLAVE_TLS_FOUND to TRUE if all listed variables are TRUE.
find_package_handle_standard_args(SGX
                                  DEFAULT_MSG
                                  SGX_INCLUDE SGX_LIBRARY_DIR)

if(SGX_FOUND)
    set(SGX_LIBRARY ${SGX_LIBRARY_PATH})
    set(SGX_INCLUDE "${SGX_PATH}/include")
    set(SGX_TLIBC_INCLUDE "${SGX_INCLUDE}/tlibc")
    set(SGX_LIBCXX_INCLUDE "${SGX_INCLUDE}/libcxx")
    set(SGX_INCLUDES ${SGX_INCLUDE} ${SGX_TLIBC_INCLUDE} ${SGX_LIBCXX_INCLUDE})
else()
    set(SGX_LIBRARY)
    set(SGX_INCLUDE)
    set(SGX_TLIBC_INCLUDE)
    set(SGX_LIBCXX_INCLUDE)
    set(SGX_INCLUDES)
endif()
