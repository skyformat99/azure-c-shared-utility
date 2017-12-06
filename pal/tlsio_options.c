// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/tlsio_options.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/crt_abstractions.h"


// The tlsio_options helper component is used only as an internal helper to
// tlsio adapters. As an internal helper it behaves conceptually like
// internal static functions, and so has the relaxed error checking of other
// internal statics.

// Initialize the TLSIO_OPTIONS struct
void tlsio_options_initialize(TLSIO_OPTIONS* options, int supported_options)
{
    // Using static function rules, so 'options' is not checked for NULL
    //
    // The supported_options value does not need validation because undefined bits are
    // ignored, while any valid missing bits result in an "option not supported" error
    // that will show up in unit testing.
    options->supported_options = supported_options;
    options->trusted_certs = NULL;
    options->x509_type = TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED;
    options->x509_cert = NULL;
    options->x509_key = NULL;
}

static int set_and_validate_x509_type(TLSIO_OPTIONS* options, TLSIO_OPTIONS_x509_TYPE x509_type)
{
    int result;
    if ((options->supported_options & x509_type) == 0)
    {
        LogError("Unsupported x509 type: %d", x509_type);
        result = __FAILURE__;
    }
    else if (options->x509_type == TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED)
    {
        options->x509_type = x509_type;
        result = 0;
    }
    else if (options->x509_type == TLSIO_OPTIONS_x509_TYPE_STANDARD)
    {
        if (x509_type != TLSIO_OPTIONS_x509_TYPE_STANDARD)
        {
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    else if (options->x509_type == TLSIO_OPTIONS_x509_TYPE_ECC)
    {
        if (x509_type != TLSIO_OPTIONS_x509_TYPE_ECC)
        {
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    else
    {
        // This can only happen if the enum definition somehow gets out of sync with this helper function
        LogError("Unexpected x509_type");
        result = __FAILURE__;
    }
    if (result != 0)
    {
        LogError("Supplied x509 type conflicts with previously set x509");
    }

    return result;
}

void tlsio_options_release_resources(TLSIO_OPTIONS* options)
{
    // Using static function rules, so 'options' is not checked for NULL
    //
    free((void*)options->trusted_certs);
    free((void*)options->x509_cert);
    free((void*)options->x509_key);
}

TLSIO_OPTIONS_RESULT tlsio_options_destroy_option(const char* name, const void* value)
{
    TLSIO_OPTIONS_RESULT result;
    if (name == NULL || value == NULL)
    {
        LogError("NULL parameter: name: %p, value: %p", name, value);
        result = TLSIO_OPTIONS_RESULT_ERROR;
    }
    else if (
        (strcmp(name, OPTION_TRUSTED_CERT) == 0) ||
        (strcmp(name, SU_OPTION_X509_CERT) == 0) ||
        (strcmp(name, SU_OPTION_X509_PRIVATE_KEY) == 0) ||
        (strcmp(name, OPTION_X509_ECC_CERT) == 0) ||
        (strcmp(name, OPTION_X509_ECC_KEY) == 0)
        )
    {
        free((void*)value);
        result = TLSIO_OPTIONS_RESULT_SUCCESS;
    }
    else
    {
        result = TLSIO_OPTIONS_RESULT_NOT_HANDLED;
    }
    return result;
}


void* tlsio_options_clone_option(const char* name, const void* value, TLSIO_OPTIONS_RESULT* out_status)
{
    void* result;
    *out_status = TLSIO_OPTIONS_RESULT_ERROR;

    if (name == NULL || value == NULL || out_status == NULL)
    {
        LogError("NULL parameter: name: %p, value: %p, out_status: %p",
            name, value, out_status);
        result = NULL;
        *out_status = TLSIO_OPTIONS_RESULT_ERROR;
    }
    else if (strcmp(name, OPTION_TRUSTED_CERT) == 0)
    {
        if (mallocAndStrcpy_s((char**)&result, value) != 0)
        {
            LogError("unable to mallocAndStrcpy_s TrustedCerts value");
            result = NULL;
        }
        else
        {
            *out_status = TLSIO_OPTIONS_RESULT_SUCCESS;
        }
    }
    else if (strcmp(name, SU_OPTION_X509_CERT) == 0)
    {
        if (mallocAndStrcpy_s((char**)&result, value) != 0)
        {
            LogError("unable to mallocAndStrcpy_s x509certificate value");
            result = NULL;
        }
        else
        {
            *out_status = TLSIO_OPTIONS_RESULT_SUCCESS;
        }
    }
    else if (strcmp(name, SU_OPTION_X509_PRIVATE_KEY) == 0)
    {
        if (mallocAndStrcpy_s((char**)&result, value) != 0)
        {
            LogError("unable to mallocAndStrcpy_s x509privatekey value");
            result = NULL;
        }
        else
        {
            *out_status = TLSIO_OPTIONS_RESULT_SUCCESS;
        }
    }
    else if (strcmp(name, OPTION_X509_ECC_CERT) == 0)
    {
        if (mallocAndStrcpy_s((char**)&result, value) != 0)
        {
            LogError("unable to mallocAndStrcpy_s x509EccCertificate value");
            result = NULL;
        }
        else
        {
            *out_status = TLSIO_OPTIONS_RESULT_SUCCESS;
        }
    }
    else if (strcmp(name, OPTION_X509_ECC_KEY) == 0)
    {
        if (mallocAndStrcpy_s((char**)&result, value) != 0)
        {
            LogError("unable to mallocAndStrcpy_s x509EccKey value");
            result = NULL;
        }
        else
        {
            *out_status = TLSIO_OPTIONS_RESULT_SUCCESS;
        }
    }
    else
    {
        result = NULL;
        *out_status = TLSIO_OPTIONS_RESULT_NOT_HANDLED;
    }
    return result;
}

TLSIO_OPTIONS_RESULT tlsio_options_set(TLSIO_OPTIONS* options,
    const char* optionName, const void* value)
{
    TLSIO_OPTIONS_RESULT result;

    if (options == NULL || optionName == NULL || value == NULL)
    {
        LogError("NULL parameter: options: %p, optionName: %p, value: %p",
            options, optionName, value);
        result = TLSIO_OPTIONS_RESULT_ERROR;
    }
    else if (strcmp(OPTION_TRUSTED_CERT, optionName) == 0)
    {
        if ((options->supported_options & TLSIO_OPTION_BIT_TRUSTED_CERTS) == 0)
        {
            LogError("Trusted certs option not supported");
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else
        {
            if (options->trusted_certs != NULL)
            {
                // Free the memory if it has been previously allocated
                free((void*)options->trusted_certs);
            }

            // Store the certificate
            if (mallocAndStrcpy_s((char**)&options->trusted_certs, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s");
                result = TLSIO_OPTIONS_RESULT_ERROR;
            }
            else
            {
                result = TLSIO_OPTIONS_RESULT_SUCCESS;
            }
        }
    }
    else if (strcmp(SU_OPTION_X509_CERT, optionName) == 0)
    {
        if (options->x509_cert != NULL)
        {
            LogError("unable to set x509 options more than once");
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else if (set_and_validate_x509_type(options, TLSIO_OPTIONS_x509_TYPE_STANDARD) != 0)
        {
            // Error logged by helper
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else
        {
            /*let's make a copy of this option*/
            if (mallocAndStrcpy_s((char**)&options->x509_cert, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s");
                result = TLSIO_OPTIONS_RESULT_ERROR;
            }
            else
            {
                result = TLSIO_OPTIONS_RESULT_SUCCESS;
            }
        }
    }
    else if (strcmp(SU_OPTION_X509_PRIVATE_KEY, optionName) == 0)
    {
        if (options->x509_key != NULL)
        {
            LogError("unable to set x509 options more than once");
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else if (set_and_validate_x509_type(options, TLSIO_OPTIONS_x509_TYPE_STANDARD) != 0)
        {
            // Error logged by helper
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else
        {
            /*let's make a copy of this option*/
            if (mallocAndStrcpy_s((char**)&options->x509_key, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s");
                result = TLSIO_OPTIONS_RESULT_ERROR;
            }
            else
            {
                result = TLSIO_OPTIONS_RESULT_SUCCESS;
            }
        }
    }
    else if (strcmp(OPTION_X509_ECC_CERT, optionName) == 0)
    {
        if (options->x509_cert != NULL)
        {
            LogError("unable to set x509 options more than once");
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else if (set_and_validate_x509_type(options, TLSIO_OPTIONS_x509_TYPE_ECC) != 0)
        {
            // Error logged by helper
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else
        {
            /*let's make a copy of this option*/
            if (mallocAndStrcpy_s((char**)&options->x509_cert, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s");
                result = TLSIO_OPTIONS_RESULT_ERROR;
            }
            else
            {
                result = TLSIO_OPTIONS_RESULT_SUCCESS;
            }
        }
    }
    else if (strcmp(OPTION_X509_ECC_KEY, optionName) == 0)
    {
        if (options->x509_key != NULL)
        {
            LogError("unable to set x509 options more than once");
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else if (set_and_validate_x509_type(options, TLSIO_OPTIONS_x509_TYPE_ECC) != 0)
        {
            // Error logged by helper
            result = TLSIO_OPTIONS_RESULT_ERROR;
        }
        else
        {
            /*let's make a copy of this option*/
            if (mallocAndStrcpy_s((char**)&options->x509_key, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s");
                result = TLSIO_OPTIONS_RESULT_ERROR;
            }
            else
            {
                result = TLSIO_OPTIONS_RESULT_SUCCESS;
            }
        }
    }
    else
    {
        result = TLSIO_OPTIONS_RESULT_NOT_HANDLED;
    }

    return result;
}

OPTIONHANDLER_HANDLE tlsio_options_retrieve_options(TLSIO_OPTIONS* options,
    pfCloneOption cloneOption, pfDestroyOption destroyOption, pfSetOption setOption)
{
    OPTIONHANDLER_HANDLE result;
    if (options == NULL)
    {
        LogError("Null parameter in options: %p, cloneOption: %p, destroyOption: %p, setOption: %p",
            options, cloneOption, destroyOption, setOption);
        result = NULL;
    }
    else
    {
        result = OptionHandler_Create(cloneOption, destroyOption, setOption);
        if (result == NULL)
        {
            LogError("OptionHandler_Create failed");
            /*return as is*/
        }
        else
        {
            if (
                (options->trusted_certs != NULL) &&
                (OptionHandler_AddOption(result, OPTION_TRUSTED_CERT, options->trusted_certs) != OPTIONHANDLER_OK)
                )
            {
                LogError("unable to save TrustedCerts option");
                OptionHandler_Destroy(result);
                result = NULL;
            }
            else if (options->x509_type != TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED)
            {
                const char* x509_cert_option = SU_OPTION_X509_CERT;
                const char* x509_key_option = SU_OPTION_X509_PRIVATE_KEY;
                if (options->x509_type == TLSIO_OPTIONS_x509_TYPE_ECC)
                {
                    x509_cert_option = OPTION_X509_ECC_CERT;
                    x509_key_option = OPTION_X509_ECC_KEY;
                }
                if (
                    (options->x509_cert != NULL) &&
                    (OptionHandler_AddOption(result, x509_cert_option, options->x509_cert) != OPTIONHANDLER_OK)
                    )
                {
                    LogError("unable to save x509 cert option");
                    OptionHandler_Destroy(result);
                    result = NULL;
                }
                else if (
                    (options->x509_key != NULL) &&
                    (OptionHandler_AddOption(result, x509_key_option, options->x509_key) != OPTIONHANDLER_OK)
                    )
                {
                    LogError("unable to save x509 key option");
                    OptionHandler_Destroy(result);
                    result = NULL;
                }
            }
        }
    }

    return result;
}

