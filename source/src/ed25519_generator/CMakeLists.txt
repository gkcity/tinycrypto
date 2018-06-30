#-----------------------------------------------------------------------------
#
# ed25519_generator
#
#-----------------------------------------------------------------------------
ADD_EXECUTABLE(ed25519_generator ed25519_generator.c)
SET_TARGET_PROPERTIES(ed25519_generator PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(ed25519_generator tiny_crypto_static ${DEPENDENCE_LIB})
