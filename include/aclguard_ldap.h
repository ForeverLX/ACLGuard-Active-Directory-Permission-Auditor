#ifndef ACLGUARD_LDAP_H
#define ACLGUARD_LDAP_H

#include "config.h"
#include "types.h"

// Fetch users from LDAP
ADUser *fetch_real_users(const Config *config, int *count_out);

#endif
