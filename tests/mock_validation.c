#include "../src/aclguard.h"
#include <assert.h>
#include <stdio.h>

void test_risk_calculations(void) {
    Permissions critical = {1, 1, 0, 0};
    assert(calculate_risk(critical) == RISK_CRITICAL);

    Permissions high_deleg = {0, 0, 0, 1};
    assert(calculate_risk(high_deleg) == RISK_HIGH);

    Permissions safe = {0, 0, 0, 0};
    assert(calculate_risk(safe) == RISK_SAFE);

    printf("[PASS] Risk calculation tests passed.\n");
}

int main(void) {
    test_risk_calculations();
    return 0;
}
