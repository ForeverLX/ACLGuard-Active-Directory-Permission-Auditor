#include "aclguard.h"
#include <stdio.h>


void handle_error(ErrorCode code) {
    const char* messages[] = {
        [E_SUCCESS] = "Success", 
        [E_LDAP_CONN] = "LDAP connection failed",
        [E_ACCESS_DENIED] = "Access denied/Insufficient permissions",
        [E_INVALID_ACL] = "Invalid ACL",
        [E_FILE_IO] = "File I/O error"
    };
    fprintf(stderr, "[!] Error %d: %s\n", code, messages[code]);
}