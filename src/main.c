// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "aclguard_ldap.h"
#include "export.h"

// Banner function
void print_banner(void) {
    printf("\n");
    printf("                █████╗  ██████╗██╗     \n");
    printf("               ██╔══██╗██╔════╝██║     \n");
    printf("               ███████║██║     ██║     \n");
    printf("               ██╔══██║██║     ██║     \n");
    printf("               ██║  ██║╚██████╗███████╗\n");
    printf("               ╚═╝  ╚═╝ ╚═════╝╚══════╝\n");
    printf("                       ForeverLX\n");
    printf("              Access Control List Guard\n\n");
}

// Function to get risk level description
const char* get_risk_level(int risk) {
    if (risk >= 80) return "🔴 CRITICAL";
    if (risk >= 60) return "🟠 HIGH";
    if (risk >= 40) return "🟡 MEDIUM";
    if (risk >= 20) return "🔵 LOW";
    return "🟢 MINIMAL";
}

// Function to display user permissions
void display_user_permissions(ADUser *user) {
    printf("    Permissions: ");
    int perm_count = 0;
    
    if (user->perms.isAdmin) {
        printf("Admin ");
        perm_count++;
    }
    if (user->perms.canResetPasswords) {
        printf("ResetPass ");
        perm_count++;
    }
    if (user->perms.canModifyACLs) {
        printf("ModifyACL ");
        perm_count++;
    }
    if (user->perms.canDelegateAuth) {
        printf("Delegate ");
        perm_count++;
    }
    if (user->perms.hasServiceAcct) {
        printf("ServiceAcct ");
        perm_count++;
    }
    if (user->perms.canReadSecrets) {
        printf("ReadSecrets ");
        perm_count++;
    }
    if (user->perms.canWriteSecrets) {
        printf("WriteSecrets ");
        perm_count++;
    }
    
    if (perm_count == 0) {
        printf("None");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    print_banner();
    
    // Parse command line arguments
    int export_csv = 0;
    int export_json = 0;
    char *csv_filename = "aclguard_users.csv";
    char *json_filename = "aclguard_users.json";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--export-csv") == 0) {
            export_csv = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                csv_filename = argv[++i];
            }
        } else if (strcmp(argv[i], "--export-json") == 0) {
            export_json = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                json_filename = argv[++i];
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --export-csv [filename]    Export results to CSV file\n");
            printf("  --export-json [filename]   Export results to JSON file\n");
            printf("  --help, -h                 Show this help message\n");
            return 0;
        }
    }

    Config config;
    if (load_env_config(&config) != 0) {
        fprintf(stderr, "❌ Failed to load configuration from environment.\n");
        return 1;
    }

    int user_count = 0;
    ADUser *users = fetch_real_users(&config, &user_count);

    if (!users || user_count == 0) {
        fprintf(stderr, "❌ LDAP connection failed or no users fetched.\n");
        return 1;
    }

    printf("✅ Successfully connected to LDAP server: %s\n", config.ldap_uri);
    printf("📊 Users retrieved: %d\n\n", user_count);

    // Display users with permissions and risk scores
    for (int i = 0; i < user_count; i++) {
        printf("═══════════════════════════════════════════════════════════════════════════════════\n");
        printf("👤 User: %s (%s)\n", 
               users[i].username ? users[i].username : "N/A",
               users[i].cn ? users[i].cn : "N/A");
        
        if (users[i].mail) {
            printf("📧 Email: %s\n", users[i].mail);
        }
        
        if (users[i].memberOf) {
            printf("👥 Groups: %s\n", users[i].memberOf);
        }
        
        display_user_permissions(&users[i]);
        printf("⚠️  Risk Score: %d/100 %s\n", users[i].risk, get_risk_level(users[i].risk));
        printf("\n");
    }

    // Summary statistics
    int high_risk_count = 0;
    int admin_count = 0;
    int privileged_count = 0;
    
    for (int i = 0; i < user_count; i++) {
        if (users[i].risk >= 60) high_risk_count++;
        if (users[i].perms.isAdmin) admin_count++;
        if (users[i].perms.isPrivileged) privileged_count++;
    }
    
    printf("═══════════════════════════════════════════════════════════════════════════════════\n");
    printf("📊 SECURITY SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════════════════════\n");
    printf("Total Users: %d\n", user_count);
    printf("High Risk Users (≥60): %d\n", high_risk_count);
    printf("Admin Users: %d\n", admin_count);
    printf("Privileged Users: %d\n", privileged_count);
    printf("═══════════════════════════════════════════════════════════════════════════════════\n");

    // Export functionality
    if (export_csv) {
        export_to_csv(csv_filename, users, user_count);
    }
    
    if (export_json) {
        export_to_json(json_filename, users, user_count);
    }

    free(users);
    return 0;
}