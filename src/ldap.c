#include "aclguard.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <ldap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

ADUser* fetch_real_users(int* count, Config* config) {
    LDAP* ld = NULL;
    int rc = ldap_initialize(&ld, config->ldap_server);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP init error: %s\n", ldap_err2string(rc));
        return NULL;
    }
    
    // Set timeout
    struct timeval timeout = {config->timeout, 0};
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    
    // Get password from environment
    char* bind_pw = getenv("LDAP_SECRET");
    if (!bind_pw) {
        fprintf(stderr, "LDAP_SECRET environment variable not set\n");
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }
    
    // Authenticate using simple bind
    struct berval cred = { strlen(bind_pw), bind_pw };
    rc = ldap_sasl_bind_s(ld, config->bind_dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP bind error: %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }
    
    // Search attributes
    char* attrs[] = {
        "distinguishedName",
        "msDS-ResetPassword",
        "userAccountControl",
        "nTSecurityDescriptor",
        NULL
    };
    
    // Perform search
    LDAPMessage* res = NULL;
    rc = ldap_search_ext_s(ld, config->search_base, LDAP_SCOPE_SUBTREE, 
                          "(objectClass=user)", attrs, 0, NULL, NULL, 
                          NULL, 0, &res);
    
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP search error: %s\n", ldap_err2string(rc));
        ldap_msgfree(res);
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }
    
    // Process results
    *count = ldap_count_entries(ld, res);
    ADUser* users = malloc(*count * sizeof(ADUser));
    LDAPMessage* entry = ldap_first_entry(ld, res);
    
    for (int i = 0; entry != NULL; i++, entry = ldap_next_entry(ld, entry)) {
        char* dn = ldap_get_dn(ld, entry);
        users[i].dn = strdup(dn);
        
        // Extract permissions
        decode_permissions(ld, entry, &users[i].perms);
        
        // Calculate risk
        users[i].risk = calculate_risk(users[i].perms);
        
        ldap_memfree(dn);
    }
    
    // Cleanup
    ldap_msgfree(res);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return users;
}