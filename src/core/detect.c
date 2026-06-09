#include "mcp-inject.h"
#include <ctype.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

typedef struct {
    char category[64];
    char** patterns;
    int pattern_count;
} SignatureSet;

static SignatureSet* g_signatures = NULL;
static int g_signature_count = 0;
static int g_signatures_loaded = 0;

static char** load_wordlist(const char* path, int* count) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        *count = 0;
        return NULL;
    }
    
    char** lines = malloc(sizeof(char*) * 1000);
    int capacity = 1000;
    int line_count = 0;
    char buffer[1024];
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        char* newline = strchr(buffer, '\n');
        if (newline) *newline = '\0';
        if (buffer[0] == '\0' || buffer[0] == '#') continue;
        
        if (line_count >= capacity) {
            capacity += 500;
            lines = realloc(lines, sizeof(char*) * capacity);
        }
        
        lines[line_count] = strdup(buffer);
        line_count++;
    }
    
    fclose(fp);
    *count = line_count;
    return lines;
}

static void free_wordlist(char** wordlist, int count) {
    if (!wordlist) return;
    for (int i = 0; i < count; i++) {
        free(wordlist[i]);
    }
    free(wordlist);
}

static const char* get_category_wordlist_path(const char* category) {
    static char path[512];
    
    if (strcmp(category, "command_injection") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/command_injection/unix_commands.txt");
    } else if (strcmp(category, "sql_injection") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/sql_injection/mysql_vectors.txt");
    } else if (strcmp(category, "path_traversal") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/path_traversal/linux_paths.txt");
    } else if (strcmp(category, "template_injection") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/template_injection/jinja2_vectors.txt");
    } else if (strcmp(category, "ssrf") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/ssrf/cloud_metadata.txt");
    } else if (strcmp(category, "xxe") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/xxe/file_read.txt");
    } else if (strcmp(category, "nosql_injection") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/nosql_injection/mongodb_vectors.txt");
    } else if (strcmp(category, "ldap_injection") == 0) {
        snprintf(path, sizeof(path), "config/wordlists/ldap_injection/bypass_vectors.txt");
    } else {
        return NULL;
    }
    
    return path;
}

static void load_all_signatures(void) {
    if (g_signatures_loaded) return;
    
    const char* categories[] = {
        "command_injection", "sql_injection", "path_traversal",
        "template_injection", "ssrf", "xxe", "nosql_injection", "ldap_injection"
    };
    int num_categories = sizeof(categories) / sizeof(char*);
    
    g_signatures = malloc(sizeof(SignatureSet) * num_categories);
    g_signature_count = 0;
    
    for (int i = 0; i < num_categories; i++) {
        const char* path = get_category_wordlist_path(categories[i]);
        if (!path) continue;
        
        char** patterns = NULL;
        int pattern_count = 0;
        
        patterns = load_wordlist(path, &pattern_count);
        
        if (!patterns || pattern_count == 0) {
            const char* fallback[] = {"root", "uid=", "error"};
            pattern_count = 3;
            patterns = malloc(sizeof(char*) * pattern_count);
            for (int j = 0; j < pattern_count; j++) {
                patterns[j] = strdup(fallback[j]);
            }
        }
        
        if (patterns && pattern_count > 0) {
            strcpy(g_signatures[g_signature_count].category, categories[i]);
            g_signatures[g_signature_count].patterns = patterns;
            g_signatures[g_signature_count].pattern_count = pattern_count;
            g_signature_count++;
        }
    }
    
    g_signatures_loaded = 1;
}

static SignatureSet* get_signatures_for_category(const char* category) {
    if (!g_signatures_loaded) {
        load_all_signatures();
    }
    
    for (int i = 0; i < g_signature_count; i++) {
        if (strcmp(g_signatures[i].category, category) == 0) {
            return &g_signatures[i];
        }
    }
    return NULL;
}

void free_all_signatures(void) {
    if (!g_signatures_loaded) return;
    
    for (int i = 0; i < g_signature_count; i++) {
        free_wordlist(g_signatures[i].patterns, g_signatures[i].pattern_count);
    }
    free(g_signatures);
    g_signatures = NULL;
    g_signature_count = 0;
    g_signatures_loaded = 0;
}

Severity get_severity_for_category(const char* category) {
    if (strcmp(category, "command_injection") == 0) return SEV_CRITICAL;
    if (strcmp(category, "template_injection") == 0) return SEV_CRITICAL;
    if (strcmp(category, "sql_injection") == 0) return SEV_HIGH;
    if (strcmp(category, "path_traversal") == 0) return SEV_HIGH;
    if (strcmp(category, "ssrf") == 0) return SEV_HIGH;
    if (strcmp(category, "xxe") == 0) return SEV_HIGH;
    return SEV_MEDIUM;
}

int pattern_match_list(const char* response, char** patterns, int pattern_count) {
    if (!response || !patterns || pattern_count == 0) return 0;
    
    char* response_lower = strdup(response);
    if (!response_lower) return 0;
    
    for (char* p = response_lower; *p; p++) {
        *p = tolower(*p);
    }
    
    for (int i = 0; i < pattern_count; i++) {
        if (strstr(response_lower, patterns[i])) {
            free(response_lower);
            return 1;
        }
    }
    
    free(response_lower);
    return 0;
}

int timing_analysis_detect(double response_time, double baseline) {
    if (baseline <= 0) return 0;
    if (response_time > baseline * 3.0) return 1;
    if (response_time > 5.0) return 1;
    return 0;
}

static int check_payload_indicators(const Payload* payload, const char* response_lower) {
    if (!payload || !response_lower) return 0;
    
    for (int i = 0; i < payload->indicator_count && i < 16; i++) {
        if (strlen(payload->detection_indicators[i]) > 0 &&
            strstr(response_lower, payload->detection_indicators[i])) {
            return 1;
        }
    }
    return 0;
}

DetectionResult* detect_vulnerability(const Payload* payload, const char* response, 
                                       int response_size, double response_time) {
    if (!payload || !response || response_size == 0) {
        return NULL;
    }
    
    DetectionResult* result = calloc(1, sizeof(DetectionResult));
    if (!result) return NULL;
    
    strncpy(result->payload_id, payload->id, sizeof(result->payload_id) - 1);
    strncpy(result->payload_name, payload->name, sizeof(result->payload_name) - 1);
    strncpy(result->category, payload->category, sizeof(result->category) - 1);
    
    result->response_time_ms = response_time * 1000;
    result->response_size = response_size;
    result->severity = payload->severity;
    result->confidence = CONF_TENTATIVE;
    
    char* response_lower = strdup(response);
    if (!response_lower) {
        free(result);
        return NULL;
    }
    
    for (char* p = response_lower; *p; p++) {
        *p = tolower(*p);
    }
    
    int payload_match = check_payload_indicators(payload, response_lower);
    
    SignatureSet* sigs = get_signatures_for_category(payload->category);
    int category_match = 0;
    char matched_pattern[256] = {0};
    
    if (sigs && sigs->pattern_count > 0) {
        for (int i = 0; i < sigs->pattern_count && !category_match; i++) {
            if (strstr(response_lower, sigs->patterns[i])) {
                category_match = 1;
                strncpy(matched_pattern, sigs->patterns[i], sizeof(matched_pattern) - 1);
                break;
            }
        }
    }
    
    int is_vulnerable = 0;
    
    if (payload_match || category_match) {
        is_vulnerable = 1;
        result->confidence = payload_match ? CONF_CERTAIN : CONF_FIRM;
        
        if (payload_match) {
            snprintf(result->evidence, sizeof(result->evidence), 
                     "Payload indicator matched in response");
        } else if (category_match) {
            snprintf(result->evidence, sizeof(result->evidence), 
                     "Signature matched: '%s' (category: %s)", 
                     matched_pattern, payload->category);
        }
    }
    
    static double baseline_time = -1;
    static int baseline_samples = 0;
    
    if (baseline_samples < 10 && response_time > 0) {
        if (baseline_time < 0) baseline_time = response_time;
        baseline_time = (baseline_time * baseline_samples + response_time) / (baseline_samples + 1);
        baseline_samples++;
    }
    
    if (is_vulnerable && timing_analysis_detect(response_time, baseline_time)) {
        result->confidence = CONF_CERTAIN;
        strncat(result->evidence, " + timing anomaly confirms", 
                sizeof(result->evidence) - strlen(result->evidence) - 1);
    }
    
    free(response_lower);
    
    if (!is_vulnerable) {
        free(result);
        return NULL;
    }
    
    return result;
}

const char* severity_to_string(Severity s) {
    switch (s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH: return "HIGH";
        case SEV_MEDIUM: return "MEDIUM";
        case SEV_LOW: return "LOW";
        case SEV_INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

const char* confidence_to_str(Confidence c) {
    switch (c) {
        case CONF_TENTATIVE: return "TENTATIVE";
        case CONF_FIRM: return "FIRM";
        case CONF_CERTAIN: return "CERTAIN";
        default: return "UNKNOWN";
    }
}

void reload_signatures(void) {
    free_all_signatures();
    load_all_signatures();
    log_info("Detection signatures reloaded from wordlists");
}