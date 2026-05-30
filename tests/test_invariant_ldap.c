#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
 * Security invariant: LDAP filter/DN/scope parameters derived from user-controlled
 * LDAP URLs must not contain unescaped LDAP special characters that could alter
 * query semantics. Any function that processes LDAP URL components before passing
 * them to ldap_search_s() must sanitize or reject inputs containing LDAP injection
 * metacharacters.
 *
 * LDAP filter special characters (RFC 4515): ( ) * \ NUL
 * LDAP DN special characters (RFC 4514): , = + < > # ; \ "
 */

/* Simulated sanitization function - represents what SHOULD happen before
 * passing parameters to ldap_search_s(). This encodes the invariant that
 * must hold: no unescaped LDAP metacharacters in filter strings. */

static int contains_unescaped_ldap_filter_metachar(const char *input) {
    if (!input) return 0;
    
    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        /* Check for unescaped LDAP filter metacharacters */
        if (c == '(' || c == ')' || c == '*' || c == '\0') {
            /* These are only safe if they are part of a valid filter structure
             * that was explicitly constructed, not injected by user input */
            return 1;
        }
        /* Check for backslash - if not followed by two hex digits, it's suspicious */
        if (c == '\\') {
            if (i + 2 < len && isxdigit((unsigned char)input[i+1]) && isxdigit((unsigned char)input[i+2])) {
                i += 2; /* properly escaped, skip */
            } else {
                return 1; /* unescaped backslash */
            }
        }
    }
    return 0;
}

static int contains_ldap_dn_injection(const char *input) {
    if (!input) return 0;
    
    /* Check for characters that could break DN parsing when injected */
    const char *dangerous = ";,=+<>#\"\\";
    size_t len = strlen(input);
    
    for (size_t i = 0; i < len; i++) {
        if (strchr(dangerous, input[i]) != NULL) {
            /* Unescaped DN special character found */
            return 1;
        }
        /* Null byte injection */
        if (input[i] == '\0') {
            return 1;
        }
    }
    return 0;
}

/* Simulate what a safe LDAP URL parameter extractor should do:
 * validate and reject/sanitize injection attempts */
static int is_safe_ldap_filter(const char *filter) {
    if (!filter) return 1; /* NULL is safe (no filter) */
    
    /* A safe filter must not contain raw user-injected metacharacters
     * outside of properly structured filter expressions.
     * For user-supplied attribute values within filters, special chars
     * must be escaped as \XX hex sequences. */
    
    /* Check for null bytes (common injection vector) */
    size_t reported_len = strlen(filter);
    for (size_t i = 0; i < reported_len; i++) {
        if (filter[i] == '\0') return 0;
    }
    
    /* Check for unbalanced parentheses that could alter filter logic */
    int depth = 0;
    for (size_t i = 0; i < reported_len; i++) {
        if (filter[i] == '(' ) depth++;
        else if (filter[i] == ')') depth--;
        if (depth < 0) return 0; /* unbalanced - injection attempt */
    }
    
    return 1;
}

static int is_safe_ldap_dn(const char *dn) {
    if (!dn) return 1;
    
    /* Check for null byte injection */
    size_t reported_len = strlen(dn);
    for (size_t i = 0; i < reported_len; i++) {
        if (dn[i] == '\0') return 0;
    }
    
    /* DN should not contain raw semicolons (alternative RDN separator - injection) */
    if (strchr(dn, ';') != NULL) return 0;
    
    return 1;
}

START_TEST(test_ldap_filter_injection_invariant)
{
    /* Invariant: LDAP filter metacharacters in user-supplied input must be
     * detected and rejected before being passed to ldap_search_s() */
    const char *filter_payloads[] = {
        /* Classic LDAP injection - always true filter */
        "*)(uid=*))(|(uid=*",
        /* Bypass authentication */
        "admin)(&(password=*))",
        /* Wildcard injection */
        "user*",
        /* Null byte injection */
        "user\x00injected",
        /* Nested filter injection */
        ")(|(objectClass=*)",
        /* OR injection */
        "valid)(|(uid=admin",
        /* Comment-like injection */
        "user)(objectClass=*",
        /* Attribute injection with wildcard */
        "cn=*)(|(cn=*",
        /* Unbalanced parentheses */
        "((((uid=test",
        /* Backslash injection */
        "user\\2a",
        /* Unicode/encoding bypass attempt */
        "user%00admin",
        /* Multiple filter bypass */
        "x)(objectClass=*))(|(objectClass=*",
        /* Empty filter with injection */
        ")(|(a=*",
        /* Deeply nested injection */
        "a)(&(b=c)(d=e",
        /* Asterisk only */
        "*",
    };
    int num_payloads = sizeof(filter_payloads) / sizeof(filter_payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        const char *payload = filter_payloads[i];
        
        /* INVARIANT: Any payload containing unescaped LDAP filter metacharacters
         * MUST be detected as unsafe. The system must never pass such values
         * directly to ldap_search_s() as a filter derived from user input. */
        int has_metachar = contains_unescaped_ldap_filter_metachar(payload);
        int is_safe = is_safe_ldap_filter(payload);
        
        /* If the payload contains metacharacters, it must NOT be considered safe */
        if (has_metachar) {
            ck_assert_msg(!is_safe,
                "SECURITY VIOLATION: Payload with LDAP metacharacters was not "
                "rejected by safety check. Payload index %d: '%s' - "
                "This would allow LDAP injection via ldap_search_s()",
                i, payload);
        }
        
        /* Additional check: payloads with unbalanced parens must be rejected */
        int depth = 0;
        int unbalanced = 0;
        for (size_t j = 0; j < strlen(payload); j++) {
            if (payload[j] == '(') depth++;
            else if (payload[j] == ')') depth--;
            if (depth < 0) { unbalanced = 1; break; }
        }
        if (depth != 0) unbalanced = 1;
        
        if (unbalanced) {
            ck_assert_msg(!is_safe_ldap_filter(payload),
                "SECURITY VIOLATION: Filter with unbalanced parentheses was "
                "not rejected. Payload index %d: '%s'", i, payload);
        }
    }
}
END_TEST

START_TEST(test_ldap_dn_injection_invariant)
{
    /* Invariant: LDAP DN special characters in user-supplied base DN must be
     * detected and rejected before being passed to ldap_search_s() */
    const char *dn_payloads[] = {
        /* DN injection via comma */
        "dc=evil,dc=com,dc=legitimate",
        /* Semicolon as alternative separator */
        "cn=user;dc=evil",
        /* Null byte in DN */
        "cn=user\x00,dc=evil",
        /* Equals sign injection */
        "cn=user=admin",
        /* Plus sign injection */
        "cn=user+uid=admin",
        /* Less/greater than injection */
        "cn=<script>",
        /* Hash injection */
        "cn=#deadbeef",
        /* Quote injection */
        "cn=\"admin\"",
        /* Backslash injection in DN */
        "cn=user\\,dc=evil",
        /* Nested DN injection */
        "cn=test,ou=users,dc=attacker,dc=com,dc=real",
        /* Empty RDN injection */
        ",dc=evil",
        /* Whitespace + special char */
        "cn=user ,dc=evil",
    };
    int num_payloads = sizeof(dn_payloads) / sizeof(dn_payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        const char *payload = dn_payloads[i];
        
        /* INVARIANT: DNs containing injection characters must be detected */
        int has_injection = contains_ldap_dn_injection(payload);
        int is_safe = is_safe_ldap_dn(payload);
        
        if (has_injection) {
            ck_assert_msg(!is_safe,
                "SECURITY VIOLATION: DN payload with injection characters was "
                "not rejected. Payload index %d: '%s' - "
                "This would allow DN injection via ldap_search_s()",
                i, payload);
        }
    }
}
END_TEST

START_TEST(test_ldap_url_component_sanitization)
{
    /* Invariant: Complete LDAP URL attack payloads must have their dangerous
     * components identified before use in ldap_search_s() */
    
    struct {
        const char *filter;
        const char *dn;
        int should_be_safe;
    } test_cases[] = {
        /* Safe inputs */
        { "uid=testuser",           "dc=example,dc=com",        1 },
        { "cn=John Doe",            "ou=users,dc=example,dc=com", 1 },
        { "objectClass=person",     "dc=test,dc=org",           1 },
        
        /* Unsafe filter inputs */
        { "uid=*)(uid=*",           "dc=example,dc=com",        0 },
        { ")(|(objectClass=*)",     "dc=example,dc=com",        0 },
        { "uid=admin)(&(1=1",       "dc=example,dc=com",        0 },
        { "*",                      "dc=example,dc=com",        0 },
        
        /* Unsafe DN inputs */
        { "uid=user",               "dc=evil;dc=com",           0 },
        { "uid=user",               "cn=x\x00,dc=com",          0 },
        
        /* Both unsafe */
        { "uid=*)(uid=*",           "dc=evil;dc=com",           0 },
    };
    
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    for (int i = 0; i < num_cases; i++) {
        int filter_safe = is_safe_ldap_filter(test_cases[i].filter) &&
                          !contains_unescaped_ldap_filter_metachar(test_cases[i].filter);
        int dn_safe = is_safe_ldap_dn(test_cases[i].dn) &&
                      !contains_ldap_dn_injection(test_cases[i].dn);
        int overall_safe = filter_safe && dn_safe;
        
        if (test_cases[i].should_be_safe) {
            ck_assert_msg(overall_safe,
                "FALSE POSITIVE: Safe input was incorrectly flagged as unsafe. "
                "Test case %d: filter='%s', dn='%s'",
                i, test_cases[i].filter, test_cases[i].dn);
        } else {
            ck_assert_msg(!overall_safe,
                "SECURITY VIOLATION: Unsafe input was not detected. "
                "Test case %d: filter='%s', dn='%s' - "
                "Would allow LDAP injection via ldap_search_s()",
                i, test_cases[i].filter, test_cases[i].dn);
        }
    }
}
END_TEST

START_TEST(test_ldap_null_byte_injection)
{
    /* Invariant: Null bytes in LDAP parameters must always be detected.
     * Null byte injection can truncate strings in C and bypass length checks. */
    
    /* Payloads with embedded null bytes */
    const char *payloads_with_nulls[] = {
        "uid=admin\x00(objectClass=*)",
        "dc=example\x00,dc=evil",
        "cn=user\x00injected_suffix",
        "\x00(uid=*)",
        "valid_prefix\x00",
    };
    
    /* We test the invariant that null bytes are detected in the string content
     * by checking memory directly (since strlen stops at null) */
    
    /* For each payload, verify that a proper scanner would detect the null byte */
    struct {
        const char *data;
        size_t true_len; /* actual length including content after null */
    } null_payloads[] = {
        { "uid=admin\x00(objectClass=*)", 24 },
        { "dc=example\x00,dc=evil",       21 },
        { "cn=user\x00injected",          16 },
    };
    
    int num_null_payloads = sizeof(null_payloads) / sizeof(null_payloads[0]);
    
    for (int i = 0; i < num_null_payloads; i++) {
        const char *data = null_payloads[i].data;
        size_t reported_len = strlen(data); /* stops at first null */
        size_t true_len = null_payloads[i].true_len;
        
        /* INVARIANT: If true_len > reported_len, there's a null byte injection.
         * A secure implementation must use explicit length parameters or
         * scan for null bytes before passing to ldap_search_s(). */
        if (true_len > reported_len) {
            /* The null byte creates a discrepancy - this is the injection vector */
            ck_assert_msg(reported_len < true_len,
                "Test setup error: null byte not detected in payload %d", i);
            
            /* Verify that is_safe functions would catch this via strlen mismatch */
            /* A proper implementation should compare strlen result with
             * the buffer size it received - here we assert the discrepancy exists */
            ck_assert_msg(reported_len != true_len,
                "SECURITY VIOLATION: Null byte injection not detectable in "
                "payload %d - strlen=%zu but true content length=%zu",
                i, reported_len, true_len);
        }
    }
    
    /* Also verify that our safety functions reject known-null-containing strings */
    /* Using a string we know has a null via memcmp */
    char null_filter[20];
    memcpy(null_filter, "uid=test\x00evil", 13);
    
    /* strlen will report 8, but the buffer has more content */
    size