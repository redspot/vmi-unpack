#include <stdio.h>
#include <config.h>

//config globals for unpack
config_t global = {
    .volatility_cmd_prefix = "",
};

//locals
static GKeyFile *key_file = NULL;

gboolean load_config_file(char *path)
{
    g_autoptr(GError) error = NULL;
    if (key_file) //singleton
        return 0;
    key_file = g_key_file_new();
    if (!g_key_file_load_from_file (key_file, path, G_KEY_FILE_NONE, &error))
    {
        fprintf(stderr, "Error loading config file {%s}: %s\n", path, error->message);
        return 0;
    }
    gchar *val = g_key_file_get_string(key_file, "global", "volatility_cmd_prefix", &error);
    if (!val)
        val = g_strdup("~/bin/");
    global.volatility_cmd_prefix = val;
    return 1;
}

void close_config_file(void)
{
    g_key_file_free(key_file);
}

void free_config(void)
{
    if (global.volatility_cmd_prefix)
        g_free(global.volatility_cmd_prefix);
}
