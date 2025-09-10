// tests/test.c
#include <stdio.h>
#include "config.h"

int main() {
    struct Config cfg = load_env_config();
    printf("LDAP URI: %s\n", cfg.ldap_uri);
    printf("Bind DN: %s\n", cfg.bind_dn);
    printf("Base DN: %s\n", cfg.base_dn);
    return 0;
}