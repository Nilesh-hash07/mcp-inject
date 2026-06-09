#ifndef MCP_INJECT_H
#define MCP_INJECT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <getopt.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define VERSION "2.0.0"
#define MAX_PAYLOADS 500
#define MAX_RESPONSE_SIZE (1024 * 1024)
#define MAX_THREADS 32
#define TIMEOUT_SEC 15
#define USER_AGENT "MCP-Inject-Scanner/2.0"

typedef enum {
    TRANSPORT_HTTP,
    TRANSPORT_WEBSOCKET,
    TRANSPORT_STDIO,
    TRANSPORT_SSE
} TransportType;

typedef enum {
    SEV_INFO = 0,
    SEV_LOW = 1,
    SEV_MEDIUM = 2,
    SEV_HIGH = 3,
    SEV_CRITICAL = 4
} Severity;

typedef enum {
    CONF_TENTATIVE = 0,
    CONF_FIRM = 1,
    CONF_CERTAIN = 2
} Confidence;

typedef struct {
    char id[32];
    char name[256];
    char category[64];
    char subcategory[64];
    char payload[2048];
    Severity severity;
    char detection_indicators[16][256];
    int indicator_count;
    char cve_id[32];
} Payload;

typedef struct {
    char payload_id[32];
    char payload_name[256];
    char category[64];
    char evidence[1024];
    Severity severity;
    Confidence confidence;
    double response_time_ms;
    int response_size;
    int http_status;
} DetectionResult;

typedef struct {
    char url[512];
    TransportType transport;
    int timeout_sec;
    int concurrent_threads;
    int rate_limit_ms;
    int verbose;
    int exploit_mode;
    int evasion_mode;
    char proxy[256];
    char user_agent[256];
} TargetConfig;

typedef struct {
    int total_payloads;
    int completed;
    int detected;
    double start_time;
    double end_time;
    double requests_per_second;
} ScanStats;

typedef struct {
    TargetConfig config;
    ScanStats stats;
    Payload* payloads;
    int payload_count;
    DetectionResult* findings;
    int findings_count;
    pthread_mutex_t findings_lock;
    pthread_mutex_t stats_lock;
    int should_stop;
} ScannerState;

typedef struct {
    char* body;
    long status_code;
    int success;
} HttpResult;

// scanner.c
ScannerState* scanner_init(TargetConfig* config);
void scanner_run(ScannerState* state);
void scanner_stop(ScannerState* state);
void scanner_free(ScannerState* state);
void scanner_save_report(ScannerState* state, const char* filename);
void scanner_get_findings(ScannerState* state, int* count);
double get_current_time_sec(void);

// payload.c
Payload* load_payloads(const char* path, int* count);
void free_payloads(Payload* payloads, int count);
void filter_payloads_by_category(Payload** payloads, int* count, const char* category);
void filter_payloads_by_severity(Payload** payloads, int* count, Severity min_sev);
void print_payload_summary(Payload* payloads, int count);

// transport.c
int transport_send(TargetConfig* config, const char* json_body, char** response);
int transport_init(void);
void transport_cleanup(void);

// detect.c
DetectionResult* detect_vulnerability(const Payload* payload, const char* response, int response_size, double response_time);
const char* severity_to_string(Severity s);
const char* confidence_to_str(Confidence c);
void free_all_signatures(void);
void reload_signatures(void);

// exploit.c
int exploit_rce(const char* target, const char* command, char** output);
int exploit_file_read(const char* target, const char* path, char** content);
int exploit_ssrf_tunnel(const char* target, const char* internal_url, char** response);
int exploit_auto(DetectionResult* finding, const char* target, char** result);

// report.c
char* report_to_json(ScannerState* state);
char* report_to_text(ScannerState* state);
char* report_to_html(ScannerState* state);
void report_save(const char* filename, const char* content);

// evasion.c
void apply_evasion(char* payload, size_t size);
char* get_random_user_agent(void);
int random_delay_ms(int min_ms, int max_ms);
char* encode_payload(const char* payload, int encoding_type);
void reload_evasion_wordlists(void);

// logger.c
void log_debug(const char* format, ...);
void log_info(const char* format, ...);
void log_warn(const char* format, ...);
void log_error(const char* format, ...);
void log_vuln(const char* severity, const char* payload_id, const char* payload_name);
void logger_init(void);
void logger_shutdown(void);
void logger_set_level(const char* level);
void logger_set_console(int enabled);
void logger_set_file(const char* filename);
void logger_banner(void);
void logger_progress(int current, int total, const char* prefix);

// crypto.c
char* base64_encode(const unsigned char* input, int length);
char* url_encode(const char* input);
char* hex_encode(const unsigned char* input, int length);
char* double_url_encode(const char* input);

#endif