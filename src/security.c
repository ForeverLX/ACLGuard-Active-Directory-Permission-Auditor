 #include "aclguard.h"
#include <ldap.h>
#include <stdio.h>

/* Existing helpers you had */
int check_password_reset(Permissions p) { return p.canResetPassword ? 1 : 0; }
int check_write_dacl(Permissions p)    { return p.hasWriteDACL ? 1 : 0; }
int check_delegation(Permissions p)    { return p.canDelegate ? 1 : 0; }

/* Minimal decode_permissions stub: set all perms to 0 and return.
 * TODO: replace with actual parsing of nTSecurityDescriptor & msDS-ResetPassword.
 */
void decode_permissions(LDAP* ld, LDAPMessage* entry, Permissions* perms) {
    if (!perms) return;
    perms->canResetPassword = 0;
    perms->hasWriteDACL = 0;
    perms->isOwner = 0;
    perms->canDelegate = 0;
    /* If you want to inspect actual attributes:
       char **vals = ldap_get_values(ld, entry, "msDS-ResetPassword");
       ... parse/interpret ...
    */