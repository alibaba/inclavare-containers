# Reference https://github.com/xzhangxa/SGX-CMake.git
include(CMakeParseArguments)

# Build edl to *_t.h and *_t.c.
# Default not support mutiple edl which cause repeated definition for sgx edl common structure.
# So need import all in one edl file for building.
function(build_edl_trust target)
    set(optionArgs USE_PREFIX)
    set(oneValueArgs EDL)
    set(multiValueArgs EDL_SEARCH_PATHS)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if("${SGX_EDL}" STREQUAL "")
        message(FATAL_ERROR "${target}: SGX enclave edl file is not provided; skipping edger8r")
    else()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file search paths are not provided!")
        endif()

        if(${SGX_USE_PREFIX})
            set(USE_PREFIX "--use-prefix")
        endif()

        set(SEARCH_PATHS "")
        foreach(path ${SGX_EDL_SEARCH_PATHS})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")

        get_filename_component(EDL_NAME ${SGX_EDL} NAME_WE)
        get_filename_component(EDL_ABSPATH ${SGX_EDL} ABSOLUTE)
        set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
        set(EDL_T_H "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")
        message("Target:[${target}], edl_t command:[${SGX_EDGER8R} ${USE_PREFIX} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}]")
        add_custom_command(OUTPUT ${EDL_T_C}
                           COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                           MAIN_DEPENDENCY ${EDL_ABSPATH}
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(${target}-edlobj OBJECT ${EDL_T_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INCLUDES})
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_T_H} ${EDL_T_C}")
    endif()
endfunction()

# Build edl to *_u.h and *_u.c
# Default not support mutiple edl which cause repeated definition for sgx edl common structure.
# So need import all in one edl file for building.
function(build_edl_untrust target)
    set(optionArgs USE_PREFIX)
    set(oneValueArgs EDL)
    set(multiValueArgs EDL_SEARCH_PATHS)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if("${SGX_EDL}" STREQUAL "")
        message(FATAL_ERROR "${target}: SGX enclave edl file is not provided; skipping edger8r")
    else()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file search paths are not provided!")
        endif()

        if(${SGX_USE_PREFIX})
            set(USE_PREFIX "--use-prefix")
        endif()

        set(SEARCH_PATHS "")
        foreach(path ${SGX_EDL_SEARCH_PATHS})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")

        get_filename_component(EDL_NAME ${SGX_EDL} NAME_WE)
        get_filename_component(EDL_ABSPATH ${SGX_EDL} ABSOLUTE)
        set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
        set(EDL_U_H "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
        message("Target:[${target}], edl_u command:[${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}]")
        add_custom_command(OUTPUT ${EDL_U_C}
                           COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                           MAIN_DEPENDENCY ${EDL_ABSPATH}
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(${target}-edlobj OBJECT ${EDL_U_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INCLUDES})
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_U_H} ${EDL_U_C}")
    endif()
endfunction()

# Build trusted static library to be linked into enclave library
function(add_trusted_library target)
    set(optionArgs USE_PREFIX)
    set(oneValueArgs EDL EDL_OBJ LDSCRIPT)
    set(multiValueArgs SRCS TRUSTED_LIBS EDL_SEARCH_PATHS)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
        get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
        set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
    endif()

    if("${SGX_EDL}" STREQUAL "" AND "${SGX_EDL_OBJ}" STREQUAL "")
        message("${target}: SGX enclave edl file is not provided; skipping edger8r")
        add_library(${target} STATIC ${SGX_SRCS})
    else()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message("${target}: SGX enclave edl file search paths are not provided!")
        endif()

        if(NOT "${SGX_EDL_OBJ}" STREQUAL "")
            add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${SGX_EDL_OBJ}>)
        elseif(NOT "${SGX_EDL}" STREQUAL "")
            if(${SGX_USE_PREFIX})
                build_edl_trust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS} USE_PREFIX ${SGX_USE_PREFIX})
            else()
                build_edl_trust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS})
            endif()
            add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        endif()
    endif()

    set(TLIB_LIST "")
    foreach(TLIB ${SGX_TRUSTED_LIBS})
        set(TLIB_LIST "${TLIB_LIST} -l${TLIB}")
    endforeach()

    set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INCLUDES})
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_T_H} ${EDL_T_C}")
endfunction()

# Build enclave shared library
function(add_enclave_library target)
    set(optionArgs USE_PREFIX)
    set(oneValueArgs EDL_OBJ LDSCRIPT)
    set(multiValueArgs SRCS TRUSTED_LIBS EDL EDL_SEARCH_PATHS)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    if("${SGX_EDL}" STREQUAL "")
        message("${target}: SGX enclave edl file is not provided!")
    endif()

    if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
        message("${target}: SGX enclave edl file search paths are not provided!")
    endif()

    if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
        get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
        set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
    endif()

    if("${SGX_EDL}" STREQUAL "" AND "${SGX_EDL_OBJ}" STREQUAL "")
        add_library(${target} SHARED ${SGX_SRCS})
    elseif(NOT "${SGX_EDL_OBJ}" STREQUAL "")
        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${SGX_EDL_OBJ}>)
    elseif(NOT "${SGX_EDL}" STREQUAL "")
        if(${SGX_USE_PREFIX})
            build_edl_trust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS} USE_PREFIX ${SGX_USE_PREFIX})
        else()
            build_edl_trust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS})
        endif()
        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
    endif()

    set(TLIB_LIST "")
    foreach(TLIB ${SGX_TRUSTED_LIBS})
        set(TLIB_LIST "${TLIB_LIST} -l${TLIB}")
    endforeach()
    set(ENCLAVE_LINK_FLAGS "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH}")
    set(ENCLAVE_LINK_FLAGS "${ENCLAVE_LINK_FLAGS} -Wl,--whole-archive ${TLIB_LIST} -l${SGX_TRTS_LIB} -Wl,--no-whole-archive")
    set(ENCLAVE_LINK_FLAGS "${ENCLAVE_LINK_FLAGS} -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -l${SGX_DCAP_TVL} -Wl,--end-group")
    set(ENCLAVE_LINK_FLAGS "${ENCLAVE_LINK_FLAGS} -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined")
    set(ENCLAVE_LINK_FLAGS "${ENCLAVE_LINK_FLAGS} -Wl,-pie,-eenclave_entry -Wl,--export-dynamic")
    set(ENCLAVE_LINK_FLAGS "${ENCLAVE_LINK_FLAGS} ${LDSCRIPT_FLAG}")
    set(ENCLAVE_LINK_FLAGS "${ENCLAVE_LINK_FLAGS} -Wl,--defsym,__ImageBase=0")

    set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INCLUDES})
    target_link_libraries(${target} ${ENCLAVE_LINK_FLAGS})
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_T_H} ${EDL_T_C}")
endfunction()

# Sign the enclave, according to configurations one-step or two-step signing will be performed.
# Default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
function(enclave_sign target)
    set(optionArgs IGNORE_INIT IGNORE_REL)
    set(oneValueArgs KEY CONFIG OUTPUT)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "" ${ARGN})
    if("${SGX_CONFIG}" STREQUAL "")
        message("${target}: SGX enclave config is not provided!")
    else()
        get_filename_component(CONFIG_ABSPATH ${SGX_CONFIG} ABSOLUTE)
    endif()
    if("${SGX_KEY}" STREQUAL "")
        if (NOT SGX_HW OR NOT SGX_RELEASE)
            message(FATAL_ERROR "${target}: Private key used to sign enclave is not provided!")
        endif()
    else()
        get_filename_component(KEY_ABSPATH ${SGX_KEY} ABSOLUTE)
    endif()
    if("${SGX_OUTPUT}" STREQUAL "")
        set(OUTPUT_NAME "${target}.signed.so")
    else()
        set(OUTPUT_NAME ${SGX_OUTPUT})
    endif()
    if(${SGX_IGNORE_INIT})
        set(IGN_INIT "-ignore-init-sec-error")
    endif()
    if(${SGX_IGNORE_REL})
        set(IGN_REL "-ignore-rel-error")
    endif()

    if(SGX_HW AND SGX_RELEASE)
        add_custom_target(${target}-sign ALL
                          COMMAND ${SGX_ENCLAVE_SIGNER} gendata
                                  $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                                  -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${target}_hash.hex ${IGN_INIT} ${IGN_REL}
                          COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                              --cyan "SGX production enclave first step signing finished, \
use ${CMAKE_CURRENT_BINARY_DIR}/${target}_hash.hex for second step"
                          WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    else()
        add_custom_target(${target}-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${KEY_ABSPATH}
                          $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                          -enclave $<TARGET_FILE:${target}>
                          -out $<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME}
                          ${IGN_INIT} ${IGN_REL}
                          WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif()

    set(CLEAN_FILES "$<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME};$<TARGET_FILE_DIR:${target}>/${target}_hash.hex")
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")
endfunction()

# Build untrusted [static|shared] library decided by '${mode}'
function(add_untrusted_library target mode)
    set(optionArgs USE_PREFIX)
    set(oneValueArgs EDL_OBJ)
    set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    if("${SGX_EDL}" STREQUAL "")
        message("${target}: SGX enclave edl file is not provided!")
    endif()

    if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
        message("${target}: SGX enclave edl file search paths are not provided!")
    endif()

    if("${SGX_EDL}" STREQUAL "" AND "${SGX_EDL_OBJ}" STREQUAL "")
        add_library(${target} ${mode} ${SGX_SRCS})
    elseif(NOT "${SGX_EDL_OBJ}" STREQUAL "")
        add_library(${target} ${mode} ${SGX_SRCS} $<TARGET_OBJECTS:${SGX_EDL_OBJ}>)
    elseif(NOT "${SGX_EDL}" STREQUAL "")
        if(${SGX_USE_PREFIX})
            build_edl_untrust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS} USE_PREFIX ${SGX_USE_PREFIX})
        else()
            build_edl_untrust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS})
        endif()
        add_library(${target} ${mode} ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
    endif()

    set(UNTRUSTED_LINK_FLAGS "-L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB} -l${SGX_DACP_QL} -l${SGX_DACP_QUOTEVERIFY} -lsgx_ukey_exchange -lpthread")

    set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INCLUDES})
    target_link_libraries(${target} ${UNTRUSTED_LINK_FLAGS})
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_U_H} ${EDL_U_C}")
endfunction()

# Build untrusted executable program
function(add_untrusted_executable target)
    set(optionArgs USE_PREFIX)
    set(oneValueArgs EDL_OBJ)
    set(multiValueArgs SRCS UNTRUSTED_LIBS EDL EDL_SEARCH_PATHS)
    cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    if("${SGX_EDL}" STREQUAL "")
        message("${target}: SGX enclave edl file is not provided!")
    endif()

    if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
        message("${target}: SGX enclave edl file search paths are not provided!")
    endif()

    if("${SGX_EDL}" STREQUAL "" AND "${SGX_EDL_OBJ}" STREQUAL "")
        add_executable(${target} ${SGX_SRCS})
    elseif(NOT "${SGX_EDL_OBJ}" STREQUAL "")
        add_executable(${target} ${SGX_SRCS} $<TARGET_OBJECTS:${SGX_EDL_OBJ}>)
    elseif(NOT "${SGX_EDL}" STREQUAL "")
        if(${SGX_USE_PREFIX})
            build_edl_untrust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS} USE_PREFIX ${SGX_USE_PREFIX})
        else()
            build_edl_untrust(${target} EDL ${SGX_EDL} EDL_SEARCH_PATHS ${SGX_EDL_SEARCH_PATHS})
        endif()
        add_executable(${target} ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
    endif()

    set(ULIB_LIST "")
    foreach(ULIB ${SGX_UNTRUSTED_LIBS})
        set (ULIB_LIST "${ULIB_LIST} ${ULIB}")
    endforeach()

    set(UNTRUSTED_LINK_FLAGS "-L${SGX_LIBRARY_PATH} ${ULIB_LIST} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB} -l${SGX_DACP_QL} -l${SGX_DACP_QUOTEVERIFY} -lsgx_ukey_exchange -lpthread")

    set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INCLUDES})
    target_link_libraries(${target} ${UNTRUSTED_LINK_FLAGS})
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_U_H} ${EDL_U_C}")
endfunction()
