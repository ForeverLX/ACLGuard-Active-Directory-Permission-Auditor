#ifndef CONFIG_H
#define CONFIG_H

#include "aclguard.h"

/* Provide a create_default_config implementation in config.c */
Config* create_default_config(void);
void free_config(Config* config);
void load_env_config(Config* config);
void apply_cli_config(Config* config, int argc, char* argv[]);

#endif // CONFIG_H