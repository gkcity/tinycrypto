/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_bignum_esp.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_BIGNUM_ESP_H__
#define __TINY_BIGNUM_ESP_H__

#include <tiny_base.h>
#include <mbedtls/bignum.h>

TINY_BEGIN_DECLS


#define tiny_mpi                    mbedtls_mpi
#define tiny_mpi_init               mbedtls_mpi_init
#define tiny_mpi_free               mbedtls_mpi_free
#define tiny_mpi_lset               mbedtls_mpi_lset
#define tiny_mpi_exp_mod            mbedtls_mpi_exp_mod
#define tiny_mpi_mul_mpi            mbedtls_mpi_mul_mpi
#define tiny_mpi_add_mpi            mbedtls_mpi_add_mpi
#define tiny_mpi_mod_mpi            mbedtls_mpi_mod_mpi
#define tiny_mpi_read_binary        mbedtls_mpi_read_binary
#define tiny_mpi_write_binary       mbedtls_mpi_write_binary
#define tiny_mpi_read_string        mbedtls_mpi_read_string


TINY_END_DECLS

#endif /* __TINY_BIGNUM_ESP_H__ */
