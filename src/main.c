#include "mcp-inject.h"
#include <signal.h>
#include <unistd.h>

static ScannerState* g_main_scanner = NULL;

static void print_usage(const char* progname) {
    printf("\n");
    printf("MCP Injection Scanner v%s\n", VERSION);
    printf("\n");
    printf("Usage: %s -t <URL> [options]\n", progname);
    printf("\n");
    printf("Required:\n");
    printf("  -t <URL>    Target MCP server URL\n");
    printf("\n");
    printf("Options:\n");
    printf("  -T <num>    Threads (default: 4)\n");
    printf("  -r <ms>     Rate limit (default: 0)\n");
    printf("  --timeout <s> Timeout seconds (default: 15)\n");
    printf("  -x <proxy>  Proxy URL\n");
    printf("  -e          Enable exploit mode\n");
    printf("  -E          Enable evasion mode\n");
    printf("  -v          Verbose output\n");
    printf("  -o <file>   Output report file\n");
    printf("  -h          Show this help\n");
    printf("\n");
    printf("Example: %s -t http://localhost:8080 -v -e -E\n", progname);
}

static void signal_handler(int sig) {
    (void)sig;
    if (g_main_scanner) {
        scanner_stop(g_main_scanner);
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    TargetConfig config;
    char* target = NULL;
    char* output_file = NULL;
    int verbose = 0;
    
    // Default config
    memset(&config, 0, sizeof(TargetConfig));
    strcpy(config.url, "http://localhost:8080");
    config.transport = TRANSPORT_HTTP;
    config.timeout_sec = 15;
    config.concurrent_threads = 4;
    config.rate_limit_ms = 0;
    config.exploit_mode = 0;
    config.evasion_mode = 0;
    strcpy(config.user_agent, "MCP-Inject-Scanner/2.0");
    config.proxy[0] = '\0';
    
    // Manual argument parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target = argv[++i];
            strcpy(config.url, target);
        }
        else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            config.concurrent_threads = atoi(argv[++i]);
            if (config.concurrent_threads < 1) config.concurrent_threads = 1;
            if (config.concurrent_threads > 32) config.concurrent_threads = 32;
        }
        else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            config.rate_limit_ms = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            config.timeout_sec = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            strcpy(config.proxy, argv[++i]);
        }
        else if (strcmp(argv[i], "-e") == 0) {
            config.exploit_mode = 1;
        }
        else if (strcmp(argv[i], "-E") == 0) {
            config.evasion_mode = 1;
        }
        else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
            config.verbose = 1;
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
        else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Initialize logger
    logger_init();
    logger_banner();
    
    // Check if target is specified
    if (!target) {
        log_error("No target specified. Use -t URL");
        print_usage(argv[0]);
        return 1;
    }
    
    // Print config
    printf("\n========================================\n");
    printf("MCP Injection Scanner Configuration\n");
    printf("========================================\n");
    printf("Target URL:     %s\n", config.url);
    printf("Threads:        %d\n", config.concurrent_threads);
    printf("Rate Limit:     %d ms\n", config.rate_limit_ms);
    printf("Timeout:        %d sec\n", config.timeout_sec);
    printf("Proxy:          %s\n", config.proxy[0] ? config.proxy : "None");
    printf("Exploit Mode:   %s\n", config.exploit_mode ? "ON" : "OFF");
    printf("Evasion Mode:   %s\n", config.evasion_mode ? "ON" : "OFF");
    printf("Verbose:        %s\n", verbose ? "ON" : "OFF");
    printf("========================================\n\n");
    
    // Initialize transport
    transport_init();
    
    // Initialize scanner
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    g_main_scanner = scanner_init(&config);
    if (!g_main_scanner) {
        log_error("Failed to initialize scanner");
        return 1;
    }
    
    // Run scan
    scanner_run(g_main_scanner);
    
    // Save report
    char default_report[256];
    if (!output_file) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(default_report, sizeof(default_report), "reports/scan_%Y%m%d_%H%M%S.json", tm_info);
        output_file = default_report;
    }
    scanner_save_report(g_main_scanner, output_file);
    
    // Get findings count
    int findings_count;
    scanner_get_findings(g_main_scanner, &findings_count);
    
    // Cleanup
    scanner_free(g_main_scanner);
    transport_cleanup();
    logger_shutdown();
    
    return findings_count > 0 ? 2 : 0;
}