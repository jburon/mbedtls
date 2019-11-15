/*
 *  Example ECDHE with Curve25519 program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#include <string.h>

#if !defined(MBEDTLS_ECDH_C) || !defined(MBEDTLS_ECDH_LEGACY_CONTEXT) || \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or MBEDTLS_ECDH_LEGACY_CONTEXT and/or "
                    "MBEDTLS_ECP_DP_CURVE25519_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"


int main( int argc, char *argv[] )
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srv[32], srv_to_cli[32];
    const char pers[] = "ecdh";
    ((void) argc);
    ((void) argv);

    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    /*
     * Initialize random number generation
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               sizeof pers ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Client: inialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up client context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_cli.grp, MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q,
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_cli.Q.X, cli_to_srv, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Server: initialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up server context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_srv.grp, MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q,
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_srv.Q.X, srv_to_cli, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Server: read peer's key and generate shared secret
     */
     /* These test vectors come from https://cr.yp.to/highspeed/naclcrypto-20090310.pdf and are repeated in RFC7748 */
     unsigned char alicesk[32] = { 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d ,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45 ,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a ,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a };

     unsigned char bobpk[32] = { 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4 ,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37 ,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d ,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f };

     unsigned char shared_bob_alice[32] = { 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1 ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25 ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33 ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 };


    mbedtls_printf( "  . Server reading client key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_srv.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.X, bobpk, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_mpi_read_binary( &ctx_srv.d, alicesk, 32 );

    /* This returns MBEDTLS_ERR_ECP_INVALID_KEY from mbedtls_ecp_check_privkey(),
      so we are probably messing up when loading ctx_srv.d */
    ret = mbedtls_ecdh_compute_shared( &ctx_srv.grp, &ctx_srv.z,
                                       &ctx_srv.Qp, &ctx_srv.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    char string_buf[2000];
    size_t olen;
    memset(string_buf, 0, sizeof string_buf);
    mbedtls_mpi_write_string(&ctx_srv.z, 16, string_buf, sizeof string_buf, &olen);
    mbedtls_printf("shared secret: %s\n", string_buf);

    /*
     * Client: read peer's key and generate shared secret
     */
    mbedtls_printf( "  . Client reading server key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_cli.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.X, srv_to_cli, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared( &ctx_cli.grp, &ctx_cli.z,
                                       &ctx_cli.Qp, &ctx_cli.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Verification: are the computed secrets equal?
     */
    mbedtls_printf( "  . Checking if both computed secrets are equal..." );
    fflush( stdout );

    ret = mbedtls_mpi_cmp_mpi( &ctx_cli.z, &ctx_srv.z );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecdh_free( &ctx_srv );
    mbedtls_ecdh_free( &ctx_cli );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( exit_code );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
