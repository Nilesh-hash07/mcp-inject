#include "mcp-inject.h"
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

static ScannerState* g_scanner_state = NULL;
static int g_scanning_active = 0;

static void* worker_thread(void* arg) {
    ScannerState* state = (ScannerState*)arg;
    
    while (1) {
        pthread_mutex_lock(&state->stats_lock);
        if (state->stats.completed >= state->stats.total_payloads || state->should_stop) {
            pthread_mutex_unlock(&state->stats_lock);
            break;
        }
        int idx = state->stats.completed++;
        pthread_mutex_unlock(&state->stats_lock);
        
        Payload* p = &state->payloads[idx];
        
        char json_rpc[8192];
        snprintf(json_rpc, sizeof(json_rpc),
            "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\","
            "\"params\":{\"name\":\"execute\",\"arguments\":{\"command\":\"%s\"},\"_scan_id\":\"%d\"},"
            "\"id\":%d}",
            p->payload, idx, idx);
        
        double start_time = get_current_time_sec();
        char* response = NULL;
        
        int transport_result = transport_send(&state->config, json_rpc, &response);
        double response_time = get_current_time_sec() - start_time;
        
        if (transport_result == 0 && response) {
            DetectionResult* dr = detect_vulnerability(p, response, strlen(response), response_time);
            
            if (dr) {
                pthread_mutex_lock(&state->findings_lock);
                state->findings[state->findings_count++] = *dr;
                pthread_mutex_unlock(&state->findings_lock);
                
                log_vuln(severity_to_string(dr->severity), p->id, p->name);
                
                if (state->config.exploit_mode && dr->severity >= SEV_HIGH) {
                    char* exploit_output = NULL;
                    if (exploit_auto(dr, state->config.url, &exploit_output) == 0) {
                        log_info("Auto-exploit successful on %s", p->id);
                        if (exploit_output) free(exploit_output);
                    }
                }
                free(dr);
            }
            free(response);
        }
        
        if (state->config.rate_limit_ms > 0) {
            usleep(state->config.rate_limit_ms * 1000);
        }
        
        pthread_mutex_lock(&state->stats_lock);
        state->stats.requests_per_second = state->stats.completed / 
            (get_current_time_sec() - state->stats.start_time);
        pthread_mutex_unlock(&state->stats_lock);
    }
    
    return NULL;
}

ScannerState* scanner_init(TargetConfig* config) {
    if (!config) return NULL;
    
    ScannerState* state = calloc(1, sizeof(ScannerState));
    if (!state) return NULL;
    
    memcpy(&state->config, config, sizeof(TargetConfig));
    
    state->payloads = load_payloads("config/payloads.json", &state->payload_count);
    
    if (!state->payloads || state->payload_count == 0) {
        log_error("No payloads loaded. Check config/payloads.json");
        free(state);
        return NULL;
    }
    
    if (state->config.concurrent_threads > MAX_THREADS) {
        state->config.concurrent_threads = MAX_THREADS;
    }
    if (state->config.concurrent_threads < 1) {
        state->config.concurrent_threads = 1;
    }
    
    state->findings = malloc(sizeof(DetectionResult) * state->payload_count);
    state->findings_count = 0;
    
    pthread_mutex_init(&state->findings_lock, NULL);
    pthread_mutex_init(&state->stats_lock, NULL);
    
    state->stats.total_payloads = state->payload_count;
    state->stats.start_time = get_current_time_sec();
    state->should_stop = 0;
    
    log_info("Scanner initialized: %d payloads, %d threads, exploit=%s, evasion=%s",
             state->stats.total_payloads,
             state->config.concurrent_threads,
             state->config.exploit_mode ? "ON" : "OFF",
             state->config.evasion_mode ? "ON" : "OFF");
    
    return state;
}

void scanner_run(ScannerState* state) {
    if (!state) return;
    
    g_scanner_state = state;
    g_scanning_active = 1;
    
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    
    log_info("Starting scan against: %s", state->config.url);
    print_payload_summary(state->payloads, state->payload_count);
    
    pthread_t threads[MAX_THREADS];
    int thread_count = state->config.concurrent_threads;
    
    for (int i = 0; i < thread_count; i++) {
        pthread_create(&threads[i], NULL, worker_thread, state);
    }
    
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    state->stats.end_time = get_current_time_sec();
    double duration = state->stats.end_time - state->stats.start_time;
    
    printf("\n\n");
    log_info("Scan complete in %.2f seconds", duration);
    log_info("Total payloads: %d", state->stats.total_payloads);
    log_info("Vulnerabilities found: %d", state->findings_count);
    log_info("Requests per second: %.2f", state->stats.requests_per_second);
    
    g_scanning_active = 0;
}

void scanner_stop(ScannerState* state) {
    if (state) {
        state->should_stop = 1;
    }
}

void scanner_free(ScannerState* state) {
    if (!state) return;
    
    free_payloads(state->payloads, state->payload_count);
    free(state->findings);
    pthread_mutex_destroy(&state->findings_lock);
    pthread_mutex_destroy(&state->stats_lock);
    free(state);
}

void scanner_save_report(ScannerState* state, const char* filename) {
    if (!state || !filename) return;
    
    char* json_report = report_to_json(state);
    if (json_report) {
        FILE* fp = fopen(filename, "w");
        if (fp) {
            fprintf(fp, "%s", json_report);
            fclose(fp);
            log_info("JSON report saved to: %s", filename);
        }
        free(json_report);
    }
    
    char* text_report = report_to_text(state);
    if (text_report) {
        printf("\n%s\n", text_report);
        free(text_report);
    }
}

void scanner_get_findings(ScannerState* state, int* count) {
    if (!state || !count) {
        *count = 0;
        return;
    }
    *count = state->findings_count;
}

double get_current_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}