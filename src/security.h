#ifndef SECURITY_H
#define SECURITY_H

#include "aclguard.h"

int check_password_reset(Permissions p);
int check_write_dacl(Permissions p);
int check_delegation(Permissions p);

#endif 