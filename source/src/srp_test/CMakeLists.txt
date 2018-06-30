#-----------------------------------------------------------------------------
#
# srp-test
#
#-----------------------------------------------------------------------------
ADD_EXECUTABLE(test_srp_hap_vectors
        test_srp_hap_vectors.c
        SrpVectors.h
        HapTestVectors.h
        HapTestVectors.c
        HapVectorsExample1.h
        HapVectorsExample1.c
    )

SET_TARGET_PROPERTIES(test_srp_hap_vectors PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(test_srp_hap_vectors tiny_crypto_static ${DEPENDENCE_LIB})

#ADD_EXECUTABLE(test_srp_random test_random.c)
#SET_TARGET_PROPERTIES(test_srp_random PROPERTIES LINKER_LANGUAGE C)
#TARGET_LINK_LIBRARIES(test_srp_random
#        iot_crypto_static
#        tiny_portable_static
#        tiny_log_static
#        tiny_base_static
#        ${OS_LIB})
