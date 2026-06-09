#include "mcp-inject.h"
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_VULN = 4
} LogLevel;

static LogLevel g_current_log_level = LOG_LEVEL_INFO;
static FILE* g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_log_to_console = 1;
static int g_log_to_file = 0;
static char g_log_filename[256] = "mcp-inject.log";

static const char* log_level_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_VULN:  return "VULN";
        default: return "UNKNOWN";
    }
}

static void get_log_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void log_debug(const char* format, ...) {
    if (LOG_LEVEL_DEBUG < g_current_log_level) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    char timestamp[32];
    get_log_timestamp(timestamp, sizeof(timestamp));
    
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    if (g_log_to_console) {
        fprintf(stderr, "%s [DEBUG] %s\n", timestamp, message);
        fflush(stderr);
    }
    
    if (g_log_to_file && g_log_file) {
        fprintf(g_log_file, "%s [DEBUG] %s\n", timestamp, message);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

void log_info(const char* format, ...) {
    if (LOG_LEVEL_INFO < g_current_log_level) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    char timestamp[32];
    get_log_timestamp(timestamp, sizeof(timestamp));
    
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    if (g_log_to_console) {
        fprintf(stderr, "%s [INFO] %s\n", timestamp, message);
        fflush(stderr);
    }
    
    if (g_log_to_file && g_log_file) {
        fprintf(g_log_file, "%s [INFO] %s\n", timestamp, message);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

void log_warn(const char* format, ...) {
    if (LOG_LEVEL_WARN < g_current_log_level) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    char timestamp[32];
    get_log_timestamp(timestamp, sizeof(timestamp));
    
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    if (g_log_to_console) {
        fprintf(stderr, "%s [WARN] %s\n", timestamp, message);
        fflush(stderr);
    }
    
    if (g_log_to_file && g_log_file) {
        fprintf(g_log_file, "%s [WARN] %s\n", timestamp, message);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

void log_error(const char* format, ...) {
    if (LOG_LEVEL_ERROR < g_current_log_level) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    char timestamp[32];
    get_log_timestamp(timestamp, sizeof(timestamp));
    
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    if (g_log_to_console) {
        fprintf(stderr, "%s [ERROR] %s\n", timestamp, message);
        fflush(stderr);
    }
    
    if (g_log_to_file && g_log_file) {
        fprintf(g_log_file, "%s [ERROR] %s\n", timestamp, message);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

void log_vuln(const char* severity, const char* payload_id, const char* payload_name) {
    if (LOG_LEVEL_VULN < g_current_log_level) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    char timestamp[32];
    get_log_timestamp(timestamp, sizeof(timestamp));
    
    char message[512];
    snprintf(message, sizeof(message), "[%s] %s - %s", severity, payload_id, payload_name);
    
    if (g_log_to_console) {
        fprintf(stderr, "%s [VULN] %s\n", timestamp, message);
        fflush(stderr);
    }
    
    if (g_log_to_file && g_log_file) {
        fprintf(g_log_file, "%s [VULN] %s\n", timestamp, message);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

void logger_set_level(const char* level) {
    if (strcmp(level, "debug") == 0) g_current_log_level = LOG_LEVEL_DEBUG;
    else if (strcmp(level, "info") == 0) g_current_log_level = LOG_LEVEL_INFO;
    else if (strcmp(level, "warn") == 0) g_current_log_level = LOG_LEVEL_WARN;
    else if (strcmp(level, "error") == 0) g_current_log_level = LOG_LEVEL_ERROR;
    else g_current_log_level = LOG_LEVEL_INFO;
}

void logger_set_console(int enabled) {
    g_log_to_console = enabled;
}

void logger_set_file(const char* filename) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    if (filename) {
        strncpy(g_log_filename, filename, sizeof(g_log_filename) - 1);
        g_log_file = fopen(g_log_filename, "a");
        if (g_log_file) {
            g_log_to_file = 1;
        } else {
            g_log_to_file = 0;
        }
    } else {
        g_log_to_file = 0;
    }
}

void logger_init(void) {
    g_current_log_level = LOG_LEVEL_INFO;
    g_log_to_console = 1;
    g_log_to_file = 0;
    log_info("Logger initialized - MCP Injection Scanner v%s", VERSION);
}

void logger_shutdown(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

void logger_banner(void) {
    if (!g_log_to_console) return;
    
    fprintf(stderr, "\n");
    fprintf(stderr, "  ╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "  ║                                                              ║\n");
    fprintf(stderr, "  ║     ███╗   ███╗ ██████╗██████╗     ██╗███╗   ██╗             ║\n");
    fprintf(stderr, "  ║     ████╗ ████║██╔════╝██╔══██╗    ██║████╗  ██║             ║\n");
    fprintf(stderr, "  ║     ██╔████╔██║██║     ██████╔╝    ██║██╔██╗ ██║             ║\n");
    fprintf(stderr, "  ║     ██║╚██╔╝██║██║     ██╔═══╝     ██║██║╚██╗██║             ║\n");
    fprintf(stderr, "  ║     ██║ ╚═╝ ██║╚██████╗██║         ██║██║ ╚████║             ║\n");
    fprintf(stderr, "  ║     ╚═╝     ╚═╝ ╚═════╝╚═╝         ╚═╝╚═╝  ╚═══╝             ║\n");
    fprintf(stderr, "  ║                                                              ║\n");
    fprintf(stderr, "  ║              MCP INJECTION SCANNER v%s                       ║\n", VERSION);
    fprintf(stderr, "  ║         Find injection vulnerabilities in MCP servers        ║\n");
    fprintf(stderr, "  ║                                                              ║\n");
    fprintf(stderr, "  ╚══════════════════════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");
}

void logger_progress(int current, int total, const char* prefix) {
    if (!g_log_to_console) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    int percent = (current * 100) / total;
    int bar_width = 40;
    int filled = (percent * bar_width) / 100;
    
    fprintf(stderr, "\r%s: [", prefix);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) fprintf(stderr, "=");
        else if (i == filled) fprintf(stderr, ">");
        else fprintf(stderr, " ");
    }
    fprintf(stderr, "] %d/%d (%d%%)", current, total, percent);
    fflush(stderr);
    
    if (current == total) {
        fprintf(stderr, "\n");
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}