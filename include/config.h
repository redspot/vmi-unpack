#ifndef CONFIG_H
#define CONFIG_H

#include <glib.h>

typedef struct {
    char *volatility_cmd_prefix;
} config_t;

extern config_t global;

gboolean load_config_file(char *path);
void close_config_file(void);
void free_config(void);

#endif
