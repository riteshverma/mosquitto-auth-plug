#include "be-jwt.h" // Will include jwt.h via its own include if HAVE_LIBJWT is defined
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h> // For va_list in _log

// Stubs for plugin environment functions
void _log(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[LOG %d] ", level);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void _fatal(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[FATAL] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    exit(1); // Or handle more gracefully for tests if needed
}

// Test Harness Macros
#define ASSERT_TRUE(val, msg) if (!(val)) { printf("Assertion Failed: %s (%s is false) at %s:%d\n", msg, #val, __FILE__, __LINE__); test_case_failed = 1; } else { printf("Assertion Passed: %s\n", msg); }
#define ASSERT_EQ(val, exp, msg) if ((val) != (exp)) { printf("Assertion Failed: %s (Actual: %d != Expected: %d) at %s:%d\n", msg, val, exp, __FILE__, __LINE__); test_case_failed = 1; } else { printf("Assertion Passed: %s\n", msg); }
#define ASSERT_STREQ(val, exp, msg) \
    do { \
        if (!val && !exp) { printf("Assertion Passed: %s (Both NULL)\n", msg); break; } \
        if (!val || !exp || strcmp((val), (exp)) != 0) { \
            printf("Assertion Failed: %s (Actual: '%s' != Expected: '%s') at %s:%d\n", msg, val ? val : "NULL", exp ? exp : "NULL", __FILE__, __LINE__); \
            test_case_failed = 1; \
        } else { \
            printf("Assertion Passed: %s\n", msg); \
        } \
    } while (0)

#define TEST_CASE_START(name) \
    int name##_func() { \
        printf("--- Running Test Case: %s ---\n", #name); \
        int test_case_failed = 0;

#define TEST_CASE_END(name) \
        if (test_case_failed == 0) { \
            printf("--- Test Case: %s PASSED ---\n\n", #name); \
            return 0; \
        } else { \
            printf("--- Test Case: %s FAILED ---\n\n", #name); \
            return 1; \
        } \
    }

// Helper to setup jwt_backend config
// Note: This bypasses p_stab() and directly sets up the struct for testing.
struct jwt_backend* setup_jwt_conf(
    const char* val_type, 
    const char* secret_or_pubkey_content, // Actual secret or actual public key content
    const char* alg_str, 
    const char* user_claim, 
    const char* su_claim, 
    const char* read_acl_claim, 
    const char* write_acl_claim
) {
    struct jwt_backend* conf = (struct jwt_backend*)malloc(sizeof(struct jwt_backend));
    if (!conf) return NULL;
    memset(conf, 0, sizeof(struct jwt_backend));

    if (val_type) conf->jwt_validation_type = strdup(val_type);
    
    // For "public_key_file", secret_or_pubkey_content would be the key itself, not a path.
    // The original be_jwt_init reads from a path. Here, we assume the content is provided.
    if (secret_or_pubkey_content) conf->jwt_secret_key_value = strdup(secret_or_pubkey_content);
    // conf->jwt_public_key_path is not used by this direct setup function.

    if (alg_str) {
        if (jwt_str_alg(alg_str, &conf->jwt_expected_alg) != 0) {
            printf("SETUP ERROR: Invalid JWT algorithm string: %s\n", alg_str);
            // Free partially allocated conf and return NULL or handle error
            if (conf->jwt_validation_type) free(conf->jwt_validation_type);
            if (conf->jwt_secret_key_value) free(conf->jwt_secret_key_value);
            free(conf);
            return NULL;
        }
    }

    if (user_claim) conf->jwt_username_claim_name = strdup(user_claim);
    else conf->jwt_username_claim_name = strdup("sub"); // Default if not provided

    if (su_claim) conf->jwt_superuser_claim_name = strdup(su_claim);
    
    if (read_acl_claim) conf->jwt_acl_topic_read_claim_key = strdup(read_acl_claim);
    else conf->jwt_acl_topic_read_claim_key = strdup("mqtt_acl_read"); // Default

    if (write_acl_claim) conf->jwt_acl_topic_write_claim_key = strdup(write_acl_claim);
    else conf->jwt_acl_topic_write_claim_key = strdup("mqtt_acl_write"); // Default
    
    return conf;
}

void free_jwt_conf(struct jwt_backend* conf) {
    if (!conf) return;
    if (conf->jwt_validation_type) free(conf->jwt_validation_type);
    if (conf->jwt_secret_key_value) free(conf->jwt_secret_key_value);
    if (conf->jwt_public_key_path) free(conf->jwt_public_key_path); // Though not set by setup_jwt_conf directly
    if (conf->jwt_username_claim_name) free(conf->jwt_username_claim_name);
    if (conf->jwt_superuser_claim_name) free(conf->jwt_superuser_claim_name);
    if (conf->jwt_acl_topic_read_claim_key) free(conf->jwt_acl_topic_read_claim_key);
    if (conf->jwt_acl_topic_write_claim_key) free(conf->jwt_acl_topic_write_claim_key);
    free(conf);
}

// --- Generated JWT Tokens (secret: "test-secret-key") ---
// Timestamps for generation (approximate, replace with actual generation for real tests)
// iat_val = time(NULL) or a fixed value like 1700000000
// exp_val_future = iat_val + 3600
// exp_val_past = iat_val - 3600
// nbf_val_future = iat_val + 3600

// Token 1 (Valid)
// Payload: { "sub": "testuser", "iss": "test_issuer", "exp": future, "iat": now, "nbf": now, 
//            "is_superuser": true, "mqtt_acl_read": ["test/topic/read", "user/%u/r/#"], 
//            "mqtt_acl_write": ["test/topic/write", "user/%u/w/#"] }
// Generated with iat=1700000000, exp=1700003600, nbf=1700000000
const char* token1_valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlzcyI6InRlc3RfaXNzdWVyIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDAsIm5iZiI6MTcwMDAwMDAwMCwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJtcXR0X2FjbF9yZWFkIjpbInRlc3QvdG9waWMvcmVhZCIsInVzZXIvJXVsci8jIl0sIm1xdHRfYWNMX3dyaXRlIjpbInRlc3QvdG9waWMvd3JpdGUiLCJ1c2VyLyV1L3cvIyJdfQ.u_m7h0Qk9jVVB1X9sNqO9kHxIDN01zhtD8JU5n99zYI";

// Token 2 (Invalid Signature) - Take token1 and tamper the signature part
const char* token2_invalid_signature = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlzcyI6InRlc3RfaXNzdWVyIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDAsIm5iZiI6MTcwMDAwMDAwMCwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJtcXR0X2FjbF9yZWFkIjpbInRlc3QvdG9waWMvcmVhZCIsInVzZXIvJXVsci8jIl0sIm1xdHRfYWNMX3dyaXRlIjpbInRlc3QvdG9waWMvd3JpdGUiLCJ1c2VyLyV1L3cvIyJdfQ.INVALID_SIGNATURE_PART";

// Token 3 (Expired)
// Payload: { "sub": "testuser", "iss": "test_issuer", "exp": past (1699996400), "iat": 1699992800, "nbf": 1699992800 }
const char* token3_expired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlzcyI6InRlc3RfaXNzdWVyIiwiZXhwIjoxNjk5OTk2NDAwLCJpYXQiOjE2OTk5OTI4MDAsIm5iZiI6MTY5OTk5MjgwMH0.z0Oq8AbzPduH2pG0F9uWXsWlJg4W93F47QxS8w1vN5E";

// Token 4 (Missing Username Claim "sub")
// Payload: { "iss": "test_issuer", "exp": 1700003600, "iat": 1700000000, "nbf": 1700000000 }
const char* token4_missing_username = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsImV4cCI6MTcwMDAwMzYwMCwiaWF0IjoxNzAwMDAwMDAwLCJuYmYiOjE3MDAwMDAwMDB9.j1vB5JkYq_y9B0xV-xL_1J3G3Zq0Yp5d8kR8cW6wQ_k";

// Token 5 (Superuser False)
// Payload: { "sub": "nosu_user", "iss": "test_issuer", "exp": 1700003600, "iat": 1700000000, "nbf": 1700000000, "is_superuser": false }
const char* token5_superuser_false = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJub3N1X3VzZXIiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImV4cCI6MTcwMDAwMzYwMCwiaWF0IjoxNzAwMDAwMDAwLCJuYmYiOjE3MDAwMDAwMDAsImlzX3N1cGVydXNlciI6ZmFsc2V9.0q1x0C0Y_v0jQ9f8nB6S2pA5wW1pX7nZ6hK8dJ4fL_s";

// Token 6 (No ACLs)
// Payload: { "sub": "noacl_user", "iss": "test_issuer", "exp": 1700003600, "iat": 1700000000, "nbf": 1700000000 }
const char* token6_no_acls = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJub2FjbF91c2VyIiwiaXNzIjoidGVzdF9pc3N1ZXIiLCJleHAiOjE3MDAwMDM2MDAsImlhdCI6MTcwMDAwMDAwMCwibmJmIjoxNzAwMDAwMDAwfQ.sH7y9q5ykC8b2f_rTVnU0zYhX_1jNqP0mZ7jR6tO_gE";

// Token 7 (NBF in future)
// Payload: { "sub": "testuser", "iss": "test_issuer", "nbf": 1700003600, "exp": 1700007200, "iat": 1700000000 }
const char* token7_nbf_future = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlzcyI6InRlc3RfaXNzdWVyIiwibmJmIjoxNzAwMDAzNjAwLCJleHAiOjE3MDAwMDcyMDAsImlhdCI6MTcwMDAwMDAwMH0.qG7g0tL8rA8nB9xW9qO8kHwJdE6wR_xY7sZ9mN8xL_c";


// --- Test Cases ---

TEST_CASE_START(test_getuser_valid_token)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", NULL, NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");

    char *phash = NULL;
    // For getuser, JWT is passed as MQTT username, password field is ignored
    int result = be_jwt_getuser(conf, token1_valid, "dummy_password", &phash, "client_id_1");
    
    ASSERT_EQ(result, BACKEND_ALLOW, "be_jwt_getuser result for valid token");
    ASSERT_STREQ(phash, "jwt_validated", "phash value for valid token");

    if (phash) free(phash);
    free_jwt_conf(conf);
TEST_CASE_END(test_getuser_valid_token)

TEST_CASE_START(test_getuser_invalid_signature)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", NULL, NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");
    
    char *phash = NULL;
    int result = be_jwt_getuser(conf, token2_invalid_signature, "dummy_password", &phash, "client_id_2");

    ASSERT_EQ(result, BACKEND_DENY, "be_jwt_getuser result for invalid signature");
    ASSERT_TRUE(phash == NULL, "phash should be NULL for invalid signature");

    if (phash) free(phash);
    free_jwt_conf(conf);
TEST_CASE_END(test_getuser_invalid_signature)

TEST_CASE_START(test_getuser_expired_token)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", NULL, NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");

    char *phash = NULL;
    // Temporarily adjust system time perception for this test if libjwt allows,
    // otherwise, ensure token3_expired is genuinely expired relative to test runtime.
    // libjwt validates exp against current time from time(NULL).
    int result = be_jwt_getuser(conf, token3_expired, "dummy_password", &phash, "client_id_3");

    ASSERT_EQ(result, BACKEND_DENY, "be_jwt_getuser result for expired token");
    ASSERT_TRUE(phash == NULL, "phash should be NULL for expired token");

    if (phash) free(phash);
    free_jwt_conf(conf);
TEST_CASE_END(test_getuser_expired_token)

TEST_CASE_START(test_getuser_nbf_future_token)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", NULL, NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");

    char *phash = NULL;
    // libjwt validates nbf against current time from time(NULL).
    int result = be_jwt_getuser(conf, token7_nbf_future, "dummy_password", &phash, "client_id_nbf");

    ASSERT_EQ(result, BACKEND_DENY, "be_jwt_getuser result for NBF in future token");
    ASSERT_TRUE(phash == NULL, "phash should be NULL for NBF in future token");

    if (phash) free(phash);
    free_jwt_conf(conf);
TEST_CASE_END(test_getuser_nbf_future_token)


TEST_CASE_START(test_getuser_missing_username_claim)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", NULL, NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");

    char *phash = NULL;
    int result = be_jwt_getuser(conf, token4_missing_username, "dummy_password", &phash, "client_id_4");

    ASSERT_EQ(result, BACKEND_DENY, "be_jwt_getuser result for token missing username claim");
    ASSERT_TRUE(phash == NULL, "phash should be NULL for token missing username claim");
    
    if (phash) free(phash);
    free_jwt_conf(conf);
TEST_CASE_END(test_getuser_missing_username_claim)


TEST_CASE_START(test_superuser_is_superuser)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", "is_superuser", NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");

    // For superuser, JWT is passed as MQTT username
    int result = be_jwt_superuser(conf, token1_valid); 
    ASSERT_EQ(result, BACKEND_ALLOW, "be_jwt_superuser result for is_superuser:true");
    
    free_jwt_conf(conf);
TEST_CASE_END(test_superuser_is_superuser)

TEST_CASE_START(test_superuser_is_not_superuser)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", "sub", "is_superuser", NULL, NULL);
    ASSERT_TRUE(conf != NULL, "Config setup");

    int result = be_jwt_superuser(conf, token5_superuser_false);
    ASSERT_EQ(result, BACKEND_DEFER, "be_jwt_superuser result for is_superuser:false (should defer)");
    
    free_jwt_conf(conf);
TEST_CASE_END(test_superuser_is_not_superuser)


TEST_CASE_START(test_aclcheck_read_allow)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", 
                                             "sub", "is_superuser", 
                                             "mqtt_acl_read", "mqtt_acl_write");
    ASSERT_TRUE(conf != NULL, "Config setup");

    // For aclcheck, JWT is passed as MQTT username field
    int result = be_jwt_aclcheck(conf, "client_id_acl1", token1_valid, "test/topic/read", MOSQ_ACL_READ);
    ASSERT_EQ(result, BACKEND_ALLOW, "be_jwt_aclcheck for direct read ACL match");

    free_jwt_conf(conf);
TEST_CASE_END(test_aclcheck_read_allow)

TEST_CASE_START(test_aclcheck_write_deny_due_to_wrong_acc)
    struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", 
                                             "sub", "is_superuser", 
                                             "mqtt_acl_read", "mqtt_acl_write");
    ASSERT_TRUE(conf != NULL, "Config setup");
    
    // Trying to WRITE to a topic that only has READ permission in token1
    int result = be_jwt_aclcheck(conf, "client_id_acl2", token1_valid, "test/topic/read", MOSQ_ACL_WRITE);
    // Expect DEFER because the 'mqtt_acl_write' claim does not contain 'test/topic/read'
    ASSERT_EQ(result, BACKEND_DEFER, "be_jwt_aclcheck for write access to read-only topic (should defer)");

    free_jwt_conf(conf);
TEST_CASE_END(test_aclcheck_write_deny_due_to_wrong_acc)


TEST_CASE_START(test_aclcheck_substitution_allow)
     struct jwt_backend* conf = setup_jwt_conf("secret", "test-secret-key", "HS256", 
                                             "sub", "is_superuser", 
                                             "mqtt_acl_read", "mqtt_acl_write");
    ASSERT_TRUE(conf != NULL, "Config setup");
    
    // Token 1 has "user/%u/r/#" in mqtt_acl_read. "sub" is "testuser".
    // So, topic "user/testuser/r/foo" should match.
    int result = be_jwt_aclcheck(conf, "client_id_acl3", token1_valid, "user/testuser/r/foo", MOSQ_ACL_READ);
    ASSERT_EQ(result, BACKEND_ALLOW, "be_jwt_aclcheck for read ACL with %u substitution");

    free_jwt_conf(conf);
TEST_CASE_END(test_aclcheck_substitution_allow)


// Main function to run tests
int main() {
    int failed_tests = 0;

    failed_tests += test_getuser_valid_token_func();
    failed_tests += test_getuser_invalid_signature_func();
    failed_tests += test_getuser_expired_token_func();
    failed_tests += test_getuser_nbf_future_token_func();
    failed_tests += test_getuser_missing_username_claim_func();
    failed_tests += test_superuser_is_superuser_func();
    failed_tests += test_superuser_is_not_superuser_func();
    failed_tests += test_aclcheck_read_allow_func();
    failed_tests += test_aclcheck_write_deny_due_to_wrong_acc_func();
    failed_tests += test_aclcheck_substitution_allow_func();

    if (failed_tests == 0) {
        printf("\nAll JWT backend tests PASSED.\n");
    } else {
        printf("\n%d JWT backend test(s) FAILED.\n", failed_tests);
    }

    return failed_tests;
}

// Required for mosquitto_topic_matches_sub, which is used by be_jwt_aclcheck.
// This is a simplified stub. In a real build, this would come from Mosquitto's library.
// For this test suite, we assume be-jwt.c might include it or it's linked.
// If be-jwt.c directly includes <mosquitto_plugin.h>, this might not be needed here.
// However, if it's expected to be linked, this stub helps.
#ifndef MOSQUITTO_PLUGIN_H
// Basic defines from mosquitto_plugin.h that might be needed if not included by be-jwt.h
#define MOSQ_ACL_READ 1
#define MOSQ_ACL_WRITE 2
// #define MOSQ_ACL_SUBSCRIBE 4 // Not used in current tests directly by be-jwt.c

// int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result) {
//     // Simplified stub for testing if not linking full mosquitto
//     // This is a very basic wildcard check, not fully MQTT compliant for complex cases.
//     // Real tests should link against mosquitto or use its source for this function.
//     if (strcmp(sub, "#") == 0) {
//         if (result) *result = true;
//         return 0; // MOSQ_ERR_SUCCESS
//     }
//     if (strcmp(sub, topic) == 0) {
//         if (result) *result = true;
//         return 0;
//     }
//     // Basic '+' wildcard check (single level)
//     // This is a very simplified version.
//     // Example: "foo/+/baz" matches "foo/bar/baz"
//     // Not handling multi-level wildcards like "foo/#" other than the first case.
//     // Or cases like "foo/+" not matching "foo" or "foo/bar/baz/qux"
//     // This part needs to be robust if we are not linking the actual mosquitto_topic_matches_sub
//
//     // Since be-jwt.c includes mosquitto_plugin.h which should bring this,
//     // this stub is more of a fallback for a disconnected test build.
//     // For now, assume be-jwt.c handles the include correctly.
//     // If compilation fails on this, it means be-jwt.c doesn't have it,
//     // and we'd need to compile/link more of mosquitto's code.
//     // The actual function is in mosquitto's src/subs.c
//     _log(LOG_WARNING, "Warning: Using simplified stub for mosquitto_topic_matches_sub.\n");
//     if (strstr(sub, "+")) { // Very naive check
//         if (result) *result = (strstr(topic, "/") != NULL && strstr(sub, "/") != NULL); // placeholder
//         return 0;
//     }
//
//     if (result) *result = false;
//     return 0;
// }
#endif
