#-----------------------------------------------------------------------------
#
# srp_generator
#
#-----------------------------------------------------------------------------
ADD_EXECUTABLE(srp_generator srp_generator.c)
SET_TARGET_PROPERTIES(srp_generator PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(srp_generator tiny_crypto_static ${DEPENDENCE_LIB})
