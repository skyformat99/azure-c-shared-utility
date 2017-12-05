// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

/**
* The gballoc.h will replace the malloc, free, and realloc by the my_gballoc functions, in this case,
*    if you define these mock functions after include the gballoc.h, you will create an infinity recursion,
*    so, places the my_gballoc functions before the #include "azure_c_shared_utility/gballoc.h"
*/
#include "gballoc_ut_impl_1.h"

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#undef ENABLE_MOCKS

#include "azure_c_shared_utility/tlsio_options.h"
#include "azure_c_shared_utility/shared_util_options.h"

#include "testrunnerswitcher.h"


static TEST_MUTEX_HANDLE g_testByTest;
static TEST_MUTEX_HANDLE g_dllByDll;

#include "gballoc_ut_impl_2.h"

const char* fake_trusted_cert = "Fake trusted cert";
const char* fake_x509_cert = "Fake x509 cert";
const char* fake_x509_key = "Fake x509 key";

#define SET_PV_COUNT 3

void ASSERT_COPIED_STRING(const char* target, const char* source)
{
    ASSERT_IS_NOT_NULL_WITH_MSG(target, "Target string is NULL");
    ASSERT_IS_NOT_NULL_WITH_MSG(target, "Source string is NULL");
    ASSERT_ARE_NOT_EQUAL_WITH_MSG(void_ptr, (void*)target, (void*)source, "Strings are duplicates instead of copies");
    ASSERT_ARE_EQUAL_WITH_MSG(char_ptr, target, source, "Strings do not match");
}

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s", ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

BEGIN_TEST_SUITE(tlsio_options_unittests)

TEST_SUITE_INITIALIZE(suite_init)
{
    TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    umock_c_init(on_umock_c_error);

    REGISTER_UMOCK_ALIAS_TYPE(TLSIO_OPTIONS_x509_TYPE, int);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

    /**
    * Or you can combine, for example, in the success case malloc will call my_gballoc_malloc, and for
    *    the failed cases, it will return NULL.
    */
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();

    TEST_MUTEX_DESTROY(g_testByTest);
    TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
}

TEST_FUNCTION_INITIALIZE(TestMethodInitialize)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("our mutex is ABANDONED. Failure in test framework");
    }

    umock_c_reset_all_calls();
    init_gballoc_checks();
}

TEST_FUNCTION_CLEANUP(TestMethodCleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}
//
//TEST_FUNCTION(tickcounter_create_fails)
//{
//    ///arrange
//    TICK_COUNTER_HANDLE tickHandle;
//    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG))
//        .IgnoreArgument(1)
//        .SetReturn((void*)NULL);
//
//    ///act
//    tickHandle = tickcounter_create();
//
//    ///assert
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//    ASSERT_IS_NULL(tickHandle);
//}

TEST_FUNCTION(tlsio_options_initialize__succeeds)
{
    ///arrange
    TLSIO_OPTIONS options;
    memset(&options, 0xff, sizeof(options));

    ///act
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_TRUSTED_CERTS | TLSIO_OPTION_BIT_x509_CERT | TLSIO_OPTION_BIT_x509_ECC_CERT);

    ///assert
    ASSERT_IS_NULL(options.trusted_certs);
    ASSERT_IS_NULL(options.x509_cert);
    ASSERT_IS_NULL(options.x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_TRUSTED_CERTS | TLSIO_OPTION_BIT_x509_CERT | TLSIO_OPTION_BIT_x509_ECC_CERT));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED);

    ///clean
}

TEST_FUNCTION(tlsio_options__set_trusted_certs__succeeds)
{
    ///arrange
    TLSIO_OPTIONS_RESULT result;
    TLSIO_OPTIONS options;
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_TRUSTED_CERTS);
    
    ///act
    result = tlsio_options_set(&options, OPTION_TRUSTED_CERT, fake_trusted_cert);

    ///assert
    ASSERT_COPIED_STRING(options.trusted_certs, fake_trusted_cert);
    ASSERT_IS_NULL(options.x509_cert);
    ASSERT_IS_NULL(options.x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_TRUSTED_CERTS));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED);
    ASSERT_ARE_EQUAL(int, (int)result, 0);

    ///clean
    tlsio_options_release_resources(&options);
    assert_gballoc_checks();
}

TEST_FUNCTION(tlsio_options__set_x509_certs__succeeds)
{
    ///arrange
    TLSIO_OPTIONS_RESULT result;
    TLSIO_OPTIONS options;
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_x509_CERT);
    
    ///act
    result = tlsio_options_set(&options, SU_OPTION_X509_CERT, fake_x509_cert);

    ///assert
    ASSERT_IS_NULL(options.trusted_certs);
    ASSERT_COPIED_STRING(options.x509_cert, fake_x509_cert);
    ASSERT_IS_NULL(options.x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_x509_CERT));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_STANDARD);
    ASSERT_ARE_EQUAL(int, (int)result, 0);

    ///clean
    tlsio_options_release_resources(&options);
    assert_gballoc_checks();
}

TEST_FUNCTION(tlsio_options__set_x509_ECC_certs__succeeds)
{
    ///arrange
    TLSIO_OPTIONS_RESULT result;
    TLSIO_OPTIONS options;
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_x509_ECC_CERT);
    
    ///act
    result = tlsio_options_set(&options, OPTION_X509_ECC_CERT, fake_x509_cert);

    ///assert
    ASSERT_IS_NULL(options.trusted_certs);
    ASSERT_COPIED_STRING(options.x509_cert, fake_x509_cert);
    ASSERT_IS_NULL(options.x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_x509_ECC_CERT));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_ECC);
    ASSERT_ARE_EQUAL(int, (int)result, 0);

    ///clean
    tlsio_options_release_resources(&options);
    assert_gballoc_checks();
}

TEST_FUNCTION(tlsio_options__set_x509_key__succeeds)
{
    ///arrange
    TLSIO_OPTIONS_RESULT result;
    TLSIO_OPTIONS options;
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_x509_CERT);

    ///act
    result = tlsio_options_set(&options, SU_OPTION_X509_PRIVATE_KEY, fake_x509_key);

    ///assert
    ASSERT_IS_NULL(options.trusted_certs);
    ASSERT_IS_NULL(options.x509_cert);
    ASSERT_COPIED_STRING(options.x509_key, fake_x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_x509_CERT));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_STANDARD);
    ASSERT_ARE_EQUAL(int, (int)result, 0);

    ///clean
    tlsio_options_release_resources(&options);
    assert_gballoc_checks();
}

TEST_FUNCTION(tlsio_options__set_x509_ECC_key__succeeds)
{
    ///arrange
    TLSIO_OPTIONS_RESULT result;
    TLSIO_OPTIONS options;
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_x509_ECC_CERT);

    ///act
    result = tlsio_options_set(&options, OPTION_X509_ECC_KEY, fake_x509_key);

    ///assert
    ASSERT_IS_NULL(options.trusted_certs);
    ASSERT_IS_NULL(options.x509_cert);
    ASSERT_COPIED_STRING(options.x509_key, fake_x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_x509_ECC_CERT));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_ECC);
    ASSERT_ARE_EQUAL(int, (int)result, 0);

    ///clean
    tlsio_options_release_resources(&options);
    assert_gballoc_checks();
}

TEST_FUNCTION(tlsio_options__set_unhandled__succeeds)
{
    ///arrange
    TLSIO_OPTIONS_RESULT result;
    TLSIO_OPTIONS options;
    tlsio_options_initialize(&options, TLSIO_OPTION_BIT_x509_ECC_CERT);

    ///act
    result = tlsio_options_set(&options, OPTION_HTTP_PROXY, fake_x509_key);

    ///assert
    ASSERT_IS_NULL(options.trusted_certs);
    ASSERT_IS_NULL(options.x509_cert);
    ASSERT_IS_NULL(options.x509_key);
    ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_x509_ECC_CERT));
    ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED);
    ASSERT_ARE_EQUAL(int, (int)result, (int)TLSIO_OPTIONS_RESULT_NOT_HANDLED);

    ///clean
    tlsio_options_release_resources(&options);
    assert_gballoc_checks();
}

TEST_FUNCTION(tlsio_options__set_parameter_validation__fails)
{
    int i;
    int k = 0;
    TLSIO_OPTIONS* p0[SET_PV_COUNT];
    const char* p1[SET_PV_COUNT];
    const char* p2[SET_PV_COUNT];
    const char* fm[SET_PV_COUNT];

    TLSIO_OPTIONS options;
    TLSIO_OPTIONS_RESULT result;

    p0[k] = NULL;     p1[k] = OPTION_TRUSTED_CERT; p2[k] = fake_x509_key; fm[k] = "Unexpected tlsio_options_initialize success when options is NULL"; /* */  k++;
    p0[k] = &options; p1[k] = NULL; /*          */ p2[k] = fake_x509_key; fm[k] = "Unexpected tlsio_options_initialize success when option_name is NULL"; k++;
    p0[k] = &options; p1[k] = OPTION_TRUSTED_CERT; p2[k] = NULL;          fm[k] = "Unexpected tlsio_options_initialize success when option_value is NULL"; k++;



    // Cycle through each failing combo of parameters
    for (i = 0; i < SET_PV_COUNT; i++)
    {
        ///arrange
        tlsio_options_initialize(&options, TLSIO_OPTION_BIT_x509_ECC_CERT);

        ///act
        result = tlsio_options_set(p0[i], p1[i], p2[i]);

        ///assert
        ASSERT_IS_NULL(options.trusted_certs);
        ASSERT_IS_NULL(options.x509_cert);
        ASSERT_IS_NULL(options.x509_key);
        ASSERT_ARE_EQUAL(int, options.supported_options, (int)(TLSIO_OPTION_BIT_x509_ECC_CERT));
        ASSERT_ARE_EQUAL(int, (int)options.x509_type, (int)TLSIO_OPTIONS_x509_TYPE_UNSPECIFIED);
        ASSERT_ARE_EQUAL_WITH_MSG(int, (int)result, (int)TLSIO_OPTIONS_RESULT_ERROR, fm[i]);

        ///clean
        tlsio_options_release_resources(&options);
        assert_gballoc_checks();
    }
}

//TEST_FUNCTION(tickcounter_destroy_tick_counter_NULL__succeeds)
//{
//    ///arrange
//
//    ///act
//    tickcounter_destroy(NULL);
//
//    ///assert
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//}
//
//TEST_FUNCTION(tickcounter_destroy__succeeds)
//{
//    ///arrange
//    TICK_COUNTER_HANDLE tickHandle = tickcounter_create();
//    umock_c_reset_all_calls();
//
//    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
//        .IgnoreArgument(1);
//
//    ///act
//    tickcounter_destroy(tickHandle);
//
//    ///assert
//    ASSERT_IS_NOT_NULL(tickHandle);
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//}
//
//TEST_FUNCTION(tickcounter_get_current_ms_tick_counter_NULL_fail)
//{
//    ///arrange
//    tickcounter_ms_t current_ms = 0;
//
//    ///act
//    int result = tickcounter_get_current_ms(NULL, &current_ms);
//
//    ///assert
//    ASSERT_ARE_NOT_EQUAL(int, 0, result);
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//}
//
//TEST_FUNCTION(tickcounter_get_current_ms_current_ms_NULL_fail)
//{
//    ///arrange
//    int result;
//    TICK_COUNTER_HANDLE tickHandle = tickcounter_create();
//    umock_c_reset_all_calls();
//
//    ///act
//    result = tickcounter_get_current_ms(tickHandle, NULL);
//
//    ///assert
//    ASSERT_ARE_NOT_EQUAL(int, 0, result);
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//
//    tickcounter_destroy(tickHandle);
//}
//
//TEST_FUNCTION(tickcounter_get_current_ms__succeeds)
//{
//    ///arrange
//    int result;
//    tickcounter_ms_t current_ms;
//    TICK_COUNTER_HANDLE tickHandle = tickcounter_create();
//    umock_c_reset_all_calls();
//
//    current_ms = 0;
//
//    ///act
//    result = tickcounter_get_current_ms(tickHandle, &current_ms);
//
//    ///assert
//    ASSERT_ARE_EQUAL(int, 0, result);
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//
//    /// clean
//    tickcounter_destroy(tickHandle);
//}
//
//TEST_FUNCTION(tickcounter_get_current_ms_validate_tick__succeeds)
//{
//    ///arrange
//    CTickCounterMocks mocks;
//    TICK_COUNTER_HANDLE tickHandle = tickcounter_create();
//    umock_c_reset_all_calls();
//
//    uint64_t first_ms = 0;
//
//    ThreadAPI_Sleep(1250);
//
//    ///act
//    int result = tickcounter_get_current_ms(tickHandle, &first_ms);
//
//    // busy loop here
//    ThreadAPI_Sleep(1250);
//
//    uint64_t next_ms = 0;
//
//    int resultAlso = tickcounter_get_current_ms(tickHandle, &next_ms);
//
//    ///assert
//    ASSERT_ARE_EQUAL(int, 0, result);
//    ASSERT_ARE_EQUAL(int, 0, resultAlso);
//    ASSERT_IS_TRUE(first_ms > 0);
//    ASSERT_IS_TRUE(next_ms > first_ms);
//    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
//
//    /// clean
//    tickcounter_destroy(tickHandle);
//}

END_TEST_SUITE(tlsio_options_unittests)
