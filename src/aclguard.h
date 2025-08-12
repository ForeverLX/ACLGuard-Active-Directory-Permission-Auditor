#ifndef ACLGUARD_H
#define ACLGUARD_H

#define LDAP_DEPRECATED 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>

/* Config struct */
typedef struct {
    char* ldap_server;
    char* bind_dn;
    char* search_base;
    int timeout;
} Config;

/* Risk types */
typedef enum {
    RISK_SAFE,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL
} RiskLevel;

/* Permissions */
typedef struct {
    int canResetPassword;
    int hasWriteDACL;
    int isOwner;
    int canDelegate;
} Permissions;

/* Active Directory user */
typedef struct {
    char* dn;
    Permissions perms;
    RiskLevel risk;
} ADUser;

/* Error codes */
typedef enum {
    E_SUCCESS = 0,
    E_LDAP_CONN,
    E_ACCESS_DENIED,
    E_INVALID_ACL,
    E_FILE_IO
} ErrorCode;

/* Data fetch / generation */
ADUser* fetch_real_users(int* count, Config* config);
ADUser* generate_mock_users(int count);

/* Exports / utilities */
void export_csv(ADUser* users, int count);
void handle_error(ErrorCode code);
const char *risk_level_to_string(RiskLevel level);
int count_critical(ADUser* users, int count);
RiskLevel calculate_risk(Permissions p);

/* Permission decoding (must implement) */
void decode_permissions(LDAP* ld, LDAPMessage* entry, Permissions* perms);

/* Config helpers */
Config* create_default_config(void);
void free_config(Config* config);
void load_env_config(Config* config);
void apply_cli_config(Config* config, int argc, char* argv[]);

/* UI */
void show_banner(void);
void show_help(void);

#endif /* ACLGUARD_H */
