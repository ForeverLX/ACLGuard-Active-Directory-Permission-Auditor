#ifndef EXPORT_H
#define EXPORT_H

#include "types.h"

void export_to_csv(const char *filename, ADUser *users, int count);
void export_to_json(const char *filename, ADUser *users, int count);

#endif