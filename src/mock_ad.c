#include "aclguard.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *risk_level_to_string(RiskLevel level) {
    switch(level) {
    case RISK_CRITICAL: return "CRITICAL";
    case RISK_HIGH:     return "HIGH";
    case RISK_MEDIUM:   return "MEDIUM";
    case RISK_LOW:      return "LOW";
    default:            return "SAFE";
    }
}

ADUser* generate_mock_users(int count) {
    if (count <= 0) return NULL;
    ADUser* users = (ADUser*)malloc(count * sizeof(ADUser));
    if (!users) return NULL;
    srand((unsigned)time(NULL));
    for (int i = 0; i < count; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "CN=MockUser%d,OU=Test,DC=local", i+1);
        users[i].dn = strdup(buf);
        Permissions perms = {
            .canResetPassword = rand() % 2,
            .hasWriteDACL     = rand() % 2,
            .isOwner          = rand() % 2,
            .canDelegate      = rand() % 2
        };
        /* seed a critical user at index 0 */
        if (i == 0) {
            perms.canResetPassword = 1;
            perms.hasWriteDACL = 1;
        }
        users[i].perms = perms;
        users[i].risk = calculate_risk(perms); /* set risk immediately */
    }
    return users;
}

int count_critical(ADUser* users, int count) {
    int critical = 0;
    for (int i = 0; i < count; i++) {
        if (users[i].risk == RISK_CRITICAL) critical++;
    }
    return critical;
}
