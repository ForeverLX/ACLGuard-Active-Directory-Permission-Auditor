#include "aclguard.h"
#include "security.h"

RiskLevel calculate_risk(Permissions p) {
    if (check_password_reset(p) && check_write_dacl(p)) return RISK_CRITICAL;
    if (check_write_dacl(p) || check_delegation(p))    return RISK_HIGH;
    if (check_password_reset(p))                       return RISK_MEDIUM;
    if (p.isOwner && !check_password_reset(p) && !check_write_dacl(p)) return RISK_LOW;
    return RISK_SAFE;
}
