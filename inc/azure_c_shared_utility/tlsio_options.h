// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TLSIO_OPTIONS_H
#define TLSIO_OPTIONS_H

#include "azure_c_shared_utility/umock_c_prod.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    // This enum identifies which options the tlsio supports
    typedef enum TLSIO_OPTION_FLAGs_TAG
    {
        TLSIO_OPTIONS_NONE = 0,
        TLSIO_OPTIONS_TRUSTED_CERTS = 0x01,
        TLSIO_OPTIONS_x509_CERT,
        TLSIO_OPTIONS_x509_KEY,
        TLSIO_OPTIONS_x509_ECC_CERT,
        TLSIO_OPTIONS_x509_ECC_KEY,

    } TLSIO_OPTION_FLAGS;

    typedef struct TLSIO_OPTIONS_TAG 
    {
        int supported_options;
        const char* trusted_certs;
        TLSIO_OPTION_FLAGS x509_cert_type;
        const char* x509_cert;
        const char* x509_key;

    } TLSIO_OPTIONS;


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TLSIO_OPTIONS_H */
