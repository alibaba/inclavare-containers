add_subdirectory(nullverifier)
if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa)
    add_subdirectory(sgx-ecdsa-qve)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()
