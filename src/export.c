#include "aclguard.h"
#include <stdio.h>
#include <stdlib.h>

static void csv_escape_and_print(FILE *fp, const char *s) {
    fputc('"', fp);
    if (s) {
        for (const char *p = s; *p; ++p) {
            if (*p == '"') fputc('"', fp);
            fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

void export_csv(ADUser* users, int count) {
    FILE* fp = fopen("./acl_report.csv", "w");
    if (!fp) {
        handle_error(E_FILE_IO);
        return;
    }
    fprintf(fp, "DN,RiskLevel,CanResetPassword,HasWriteDACL,CanDelegate\n");
    for (int i = 0; i < count; i++) {
        csv_escape_and_print(fp, users[i].dn);
        fprintf(fp, ",%s,%d,%d,%d\n",
                risk_level_to_string(users[i].risk),
                users[i].perms.canResetPassword,
                users[i].perms.hasWriteDACL,
                users[i].perms.canDelegate);
    }
    if (fclose(fp) == EOF) handle_error(E_FILE_IO);
}
