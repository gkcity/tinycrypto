/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_bignum_polarssl.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_BIGNUM_POLARSSL_H__
#define __TINY_BIGNUM_POLARSSL_H__

#include <tiny_base.h>
#include "polarssl/bignum.h"

TINY_BEGIN_DECLS


#define tiny_mpi                    mpi
#define tiny_mpi_init               mpi_init
#define tiny_mpi_free               mpi_free
#define tiny_mpi_lset               mpi_lset
#define tiny_mpi_exp_mod            mpi_exp_mod
#define tiny_mpi_mul_mpi            mpi_mul_mpi
#define tiny_mpi_add_mpi            mpi_add_mpi
#define tiny_mpi_mod_mpi            mpi_mod_mpi
#define tiny_mpi_read_binary        mpi_read_binary
#define tiny_mpi_write_binary       mpi_write_binary
#define tiny_mpi_read_string        mpi_read_string
#define tiny_mpi_write_string       mpi_write_string


TINY_END_DECLS

#endif /* __TINY_BIGNUM_POLARSSL_H__ */