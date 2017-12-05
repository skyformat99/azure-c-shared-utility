// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// tlsio_options handles only the most commonly-used options for tlsio adapters. Options
// not supported by this component may be handled in the tlsio adapter instead.

#ifndef TLSIO_OPTIONS_H
#define TLSIO_OPTIONS_H

#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/umock_c_prod.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    // This enum identifies individual options
    typedef enum TLSIO_OPTION_BIT_TAG
    {
        TLSIO_OPTION_BIT_NONE =          0x00,
        TLSIO_OPTION_BIT_TRUSTED_CERTS = 0x01,
        TLSIO_OPTION_BIT_x509_CERT =     0x02,
        TLSIO_OPTION_BIT_x509_ECC_CERT = 0x04,
    } TLSIO_OPTION_BIT;

    typedef enum TLSIO_OPTIONS_x509_TYPE_TAG
    {
        TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED = TLSIO_OPTION_BIT_NONE,
        TLSIO_OPTIONS_x509_TYPE_STANDARD = TLSIO_OPTION_BIT_x509_CERT,
        TLSIO_OPTIONS_x509_TYPE_ECC = TLSIO_OPTION_BIT_x509_ECC_CERT
    } TLSIO_OPTIONS_x509_TYPE;

    typedef enum TLSIO_OPTIONS_RESULT_TAG
    {
        TLSIO_OPTIONS_RESULT_SUCCESS,
        TLSIO_OPTIONS_RESULT_NOT_HANDLED,
        TLSIO_OPTIONS_RESULT_ERROR
    } TLSIO_OPTIONS_RESULT;


    // This struct contains the commonly-used options which
    // are supported by tlsio_options.
    typedef struct TLSIO_OPTIONS_TAG 
    {
        int supported_options;
        const char* trusted_certs;
        TLSIO_OPTIONS_x509_TYPE x509_type;
        const char* x509_cert;
        const char* x509_key;
    } TLSIO_OPTIONS;

    // Initialize the TLSIO_OPTIONS struct and specify which options are supported as a bit-or'ed
    // set of TLSIO_OPTION_BIT. For the x509 certs, only the *_CERT bit need be specified; the *_KEY
    // is understood to go with the cert.
    void tlsio_options_initialize(TLSIO_OPTIONS* options, int option_caps);

    TLSIO_OPTIONS_RESULT tlsio_options_set(TLSIO_OPTIONS* options,  
        const char* optionName, const void* value);

    void tlsio_options_release_resources(TLSIO_OPTIONS* options);

    void* tlsio_options_clone_option(const char* name, const void* value, TLSIO_OPTIONS_RESULT* out_status);

    TLSIO_OPTIONS_RESULT tlsio_options_destroy_option(const char* name, const void* value);

    OPTIONHANDLER_HANDLE tlsio_options_retrieve_options(TLSIO_OPTIONS* options, 
        pfCloneOption cloneOption, pfDestroyOption destroyOption, pfSetOption setOption);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TLSIO_OPTIONS_H */
