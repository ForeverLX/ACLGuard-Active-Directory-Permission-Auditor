// src/main.c
#include "aclguard.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void show_banner() {
    printf("\n");
    printf("  ___  ____  \n");
    printf(" / _ |/ __ \\ \n");
    printf("/ /_| | / / / /\n");
    printf("\\___ |/ /_/ / \n");
    printf("    |_\\_____/  \n");
    printf("Active Directory ACL Scanner\n\n");
}

void show_help() {
    printf("Usage: ./ACLGuard [--mock] [--ldap] [--export] [--critical]\n");
    printf("Options:\n");
    printf("  --mock      Use mock data\n");
    printf("  --ldap      Connect to real AD\n");
    printf("  --export    Generate CSV report\n");
    printf("  --critical  Show only critical risks\n");
    printf("  --version   Show version\n");
    printf("  --help      Show this help\n");
}

int main(int argc, char *argv[]) {
    show_banner();

    /* Flags (single declaration) */
    int mock_mode = 0, ldap_mode = 0, export_mode = 0;
    int critical_only = 0, version_mode = 0, help_mode = 0;

    /* Create and load config */
    Config *config = create_default_config();
    if (!config) {
        fprintf(stderr, "Error: failed to allocate config\n");
        return 1;
    }
    load_env_config(config);
    apply_cli_config(config, argc, argv);

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mock") == 0) mock_mode = 1;
        else if (strcmp(argv[i], "--ldap") == 0) ldap_mode = 1;
        else if (strcmp(argv[i], "--export") == 0) export_mode = 1;
        else if (strcmp(argv[i], "--critical") == 0) critical_only = 1;
        else if (strcmp(argv[i], "--version") == 0) version_mode = 1;
        else if (strcmp(argv[i], "--help") == 0) help_mode = 1;
    }

    if (version_mode) {
        printf("ACLGuard DEFCON Edition v1.0\n");
        free_config(config);
        return 0;
    }
    if (help_mode || argc == 1) {
        show_help();
        free_config(config);
        return 0;
    }

    if ((mock_mode + ldap_mode) != 1) {
        fprintf(stderr, "Error: Specify exactly one of --mock or --ldap\n");
        show_help();
        free_config(config);
        return 1;
    }

    if (config->ldap_server) printf("Using LDAP server: %s\n", config->ldap_server);
    if (config->bind_dn)     printf("Bind DN: %s\n", config->bind_dn);
    if (config->search_base) printf("Search Base: %s\n", config->search_base);
    printf("Timeout: %d seconds\n", config->timeout);

    /* Generate user data */
    int user_count = 0;
    ADUser *users = NULL;

    if (mock_mode) {
        printf("[+] Using mock data\n");
        user_count = 10;
        users = generate_mock_users(user_count);
        if (!users) {
            fprintf(stderr, "Error: generate_mock_users failed\n");
            free_config(config);
            return 1;
        }
    } else { /* ldap_mode == 1 */
        printf("[+] Connecting to LDAP server\n");
        users = fetch_real_users(&user_count, config);
        if (!users || user_count == 0) {
            fprintf(stderr, "Error: No users retrieved from LDAP\n");
            free_config(config);
            return 1;
        }
    }

    /* (If mock generator didn't set risks) ensure we calculate risk */
    for (int i = 0; i < user_count; i++) {
        users[i].risk = calculate_risk(users[i].perms);
    }

    /* Optional: filter critical only */
    if (critical_only) {
        int critical_count = 0;
        ADUser* critical_users = NULL;
        for (int i = 0; i < user_count; i++) {
            if (users[i].risk == RISK_CRITICAL) {
                ADUser *tmp = realloc(critical_users, (critical_count + 1) * sizeof(ADUser));
                if (!tmp) {
                    fprintf(stderr, "Memory allocation failure\n");
                    free(critical_users);
                    free_config(config);
                    return 1;
                }
                critical_users = tmp;
                critical_users[critical_count++] = users[i];
            }
        }
        /* release the original array memory for DN strings ownership is transferred */
        free(users);
        users = critical_users;
        user_count = critical_count;
    }

    /* Output or export */
    if (export_mode) {
        export_csv(users, user_count);
        printf("[+] Report exported to acl_report.csv\n");
    } else {
        printf("\n═══════════════════════════════════\n");
        printf(" ACL RISK ASSESSMENT REPORT\n");
        printf("═══════════════════════════════════\n\n");
        for (int i = 0; i < user_count; i++) {
            const char *risk_str = risk_level_to_string(users[i].risk);
            printf("DN: %s\n", users[i].dn ? users[i].dn : "(null)");
            printf("Risk: %s\n", risk_str);
            printf("Permissions: PasswordReset=%d, WriteDACL=%d, Delegation=%d\n\n",
                   users[i].perms.canResetPassword,
                   users[i].perms.hasWriteDACL,
                   users[i].perms.canDelegate);
        }
        printf("═══════════════════════════════════\n");
        printf("Scanned Users: %d\n", user_count);
        printf("Critical Risks: %d\n", critical_only ? user_count : count_critical(users, user_count));
        printf("═══════════════════════════════════\n");
    }

    /* Cleanup */
    for (int i = 0; i < user_count; i++) free(users[i].dn);
    free(users);
    free_config(config);
    return 0;
}
