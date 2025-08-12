// src/config.c
#include "aclguard.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

Config* create_default_config(void) {
    Config* cfg = (Config*)calloc(1, sizeof(Config));
    if (!cfg) return NULL;
    cfg->ldap_server = NULL;
    cfg->bind_dn = NULL;
    cfg->search_base = NULL;
    cfg->timeout = 10; /* default */
    return cfg;
}

void load_env_config(Config* config) {
    if (!config) return;
    char* server = getenv("LDAP_SERVER");
    char* bind_dn = getenv("LDAP_BIND_DN");
    char* base = getenv("LDAP_SEARCH_BASE");
    if (server) {
        free(config->ldap_server);
        config->ldap_server = strdup(server);
    }
    if (bind_dn) {
        free(config->bind_dn);
        config->bind_dn = strdup(bind_dn);
    }
    if (base) {
        free(config->search_base);
        config->search_base = strdup(base);
    }
}

void apply_cli_config(Config* config, int argc, char* argv[]) {
    if (!config) return;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i+1 < argc) {
            free(config->ldap_server);
            config->ldap_server = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--bind-dn") == 0 && i+1 < argc) {
            free(config->bind_dn);
            config->bind_dn = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--base") == 0 && i+1 < argc) {
            free(config->search_base);
            config->search_base = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i+1 < argc) {
            config->timeout = atoi(argv[++i]);
        }
    }
}

void free_config(Config* config) {
    if (!config) return;
    free(config->ldap_server);
    free(config->bind_dn);
    free(config->search_base);
    free(config);
}
