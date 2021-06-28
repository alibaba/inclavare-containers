add_subdirectory(nullattester)
if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()
