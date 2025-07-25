#include "deadlight.h"

gboolean deadlight_test_module(const gchar *module_name) {
    g_return_val_if_fail(module_name != NULL, FALSE);
    
    g_print("Testing module: %s\n", module_name);
    
    // TODO: Implement module testing
    return TRUE;
}

gchar *deadlight_format_bytes(guint64 bytes) {
    if (bytes < 1024) {
        return g_strdup_printf("%lu B", bytes);
    } else if (bytes < 1024 * 1024) {
        return g_strdup_printf("%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        return g_strdup_printf("%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        return g_strdup_printf("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

gchar *deadlight_format_duration(gdouble seconds) {
    if (seconds < 60) {
        return g_strdup_printf("%.1f seconds", seconds);
    } else if (seconds < 3600) {
        return g_strdup_printf("%.1f minutes", seconds / 60.0);
    } else if (seconds < 86400) {
        return g_strdup_printf("%.1f hours", seconds / 3600.0);
    } else {
        return g_strdup_printf("%.1f days", seconds / 86400.0);
    }
}
