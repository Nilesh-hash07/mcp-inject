#include "mcp-inject.h"
#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

// ========== Wordlist Cache for Payload Expansion ==========

typedef struct {
    char* name;
    char** entries;
    int count;
} PayloadWordlist;

static PayloadWordlist g_payload_wordlists[30];
static int g_payload_wordlist_count = 0;
static int g_payload_wordlists_loaded = 0;

// ========== Expanded Payload Storage ==========

typedef struct {
    Payload base;
    char** variants;
    int variant_count;
} ExpandedPayload;

static ExpandedPayload* g_expanded_payloads = NULL;
static int g_expanded_payload_count = 0;

// ========== Wordlist Loading Functions ==========

static char** load_payload_wordlist(const char* path, int* count) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        *count = 0;
        return NULL;
    }
    
    char** lines = malloc(sizeof(char*) * 5000);
    int capacity = 5000;
    int line_count = 0;
    char buffer[2048];
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        char* newline = strchr(buffer, '\n');
        if (newline) *newline = '\0';
        
        if (buffer[0] == '\0' || buffer[0] == '#') continue;
        
        if (line_count >= capacity) {
            capacity += 1000;
            lines = realloc(lines, sizeof(char*) * capacity);
        }
        
        lines[line_count] = strdup(buffer);
        line_count++;
    }
    
    fclose(fp);
    *count = line_count;
    return lines;
}

static void free_payload_wordlist(char** entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        free(entries[i]);
    }
    free(entries);
}

static void load_all_payload_wordlists(void) {
    if (g_payload_wordlists_loaded) return;
    
    struct {
        const char* name;
        const char* path;
    } wordlist_defs[] = {
        // Command injection wordlists
        {"unix_commands", "config/wordlists/command_injection/unix_commands.txt"},
        {"windows_commands", "config/wordlists/command_injection/windows_commands.txt"},
        {"reverse_shells", "config/wordlists/command_injection/reverse_shells.txt"},
        {"time_based", "config/wordlists/command_injection/time_based.txt"},
        
        // Path traversal wordlists
        {"linux_paths", "config/wordlists/path_traversal/linux_paths.txt"},
        {"windows_paths", "config/wordlists/path_traversal/windows_paths.txt"},
        {"traversal_bypass", "config/wordlists/path_traversal/bypass_patterns.txt"},
        {"encoded_variants", "config/wordlists/path_traversal/encoded_variants.txt"},
        
        // SQL injection wordlists
        {"mysql_vectors", "config/wordlists/sql_injection/mysql_vectors.txt"},
        {"postgres_vectors", "config/wordlists/sql_injection/postgres_vectors.txt"},
        {"union_selects", "config/wordlists/sql_injection/union_selects.txt"},
        {"blind_time", "config/wordlists/sql_injection/blind_time_based.txt"},
        {"waf_bypass", "config/wordlists/sql_injection/waf_bypass.txt"},
        
        // Template injection wordlists
        {"jinja2_vectors", "config/wordlists/template_injection/jinja2_vectors.txt"},
        {"twig_vectors", "config/wordlists/template_injection/twig_vectors.txt"},
        
        // SSRF wordlists
        {"cloud_metadata", "config/wordlists/ssrf/cloud_metadata.txt"},
        {"internal_services", "config/wordlists/ssrf/internal_services.txt"},
        
        // XXE wordlists
        {"xxe_file_read", "config/wordlists/xxe/file_read.txt"},
        
        // NoSQL wordlists
        {"mongodb_vectors", "config/wordlists/nosql_injection/mongodb_vectors.txt"},
        
        // LDAP wordlists
        {"ldap_bypass", "config/wordlists/ldap_injection/bypass_vectors.txt"},
        
        // Evasion wordlists
        {"polyglots", "config/wordlists/evasion/polyglots.txt"}
    };
    int num_defs = sizeof(wordlist_defs) / sizeof(wordlist_defs[0]);
    
    for (int i = 0; i < num_defs && g_payload_wordlist_count < 30; i++) {
        int count = 0;
        char** entries = load_payload_wordlist(wordlist_defs[i].path, &count);
        
        if (entries && count > 0) {
            g_payload_wordlists[g_payload_wordlist_count].name = strdup(wordlist_defs[i].name);
            g_payload_wordlists[g_payload_wordlist_count].entries = entries;
            g_payload_wordlists[g_payload_wordlist_count].count = count;
            g_payload_wordlist_count++;
            log_info("Payload: Loaded %d entries from %s", count, wordlist_defs[i].path);
        }
    }
    
    g_payload_wordlists_loaded = 1;
}

static char** get_payload_wordlist(const char* name, int* count) {
    if (!g_payload_wordlists_loaded) {
        load_all_payload_wordlists();
    }
    
    for (int i = 0; i < g_payload_wordlist_count; i++) {
        if (strcmp(g_payload_wordlists[i].name, name) == 0) {
            *count = g_payload_wordlists[i].count;
            return g_payload_wordlists[i].entries;
        }
    }
    
    *count = 0;
    return NULL;
}

// ========== Payload Expansion Functions ==========

static char* expand_command_injection_payload(const char* base_payload, const char* command) {
    char* result = malloc(2048);
    if (!result) return NULL;
    
    // Replace common placeholders or just append command
    if (strstr(base_payload, "CMD")) {
        char* temp = strdup(base_payload);
        char* pos = strstr(temp, "CMD");
        if (pos) {
            *pos = '\0';
            snprintf(result, 2048, "%s%s%s", temp, command, pos + 3);
        } else {
            snprintf(result, 2048, "%s", base_payload);
        }
        free(temp);
    } else if (strstr(base_payload, "whoami") || strstr(base_payload, "id")) {
        // Replace the example command with actual target
        char* temp = strdup(base_payload);
        char* pos = strstr(temp, "whoami");
        if (!pos) pos = strstr(temp, "id");
        if (pos) {
            *pos = '\0';
            snprintf(result, 2048, "%s%s%s", temp, command, pos + (strstr(base_payload, "whoami") ? 6 : 2));
        } else {
            snprintf(result, 2048, "%s", base_payload);
        }
        free(temp);
    } else {
        snprintf(result, 2048, "%s %s", base_payload, command);
    }
    
    return result;
}

static char* expand_path_traversal_payload(const char* base_payload, const char* path) {
    char* result = malloc(2048);
    if (!result) return NULL;
    
    if (strstr(base_payload, "/etc/passwd") || strstr(base_payload, "win.ini")) {
        char* temp = strdup(base_payload);
        char* pos = strstr(temp, "/etc/passwd");
        if (!pos) pos = strstr(temp, "win.ini");
        if (pos) {
            *pos = '\0';
            snprintf(result, 2048, "%s%s%s", temp, path, pos + (strstr(base_payload, "/etc/passwd") ? 11 : 7));
        } else {
            snprintf(result, 2048, "%s", base_payload);
        }
        free(temp);
    } else {
        snprintf(result, 2048, "%s%s", base_payload, path);
    }
    
    return result;
}

static char* expand_template_injection_payload(const char* base_payload, const char* command) {
    char* result = malloc(2048);
    if (!result) return NULL;
    
    if (strstr(base_payload, "whoami") || strstr(base_payload, "id") || strstr(base_payload, "7*7")) {
        char* temp = strdup(base_payload);
        char* pos = strstr(temp, "whoami");
        if (!pos) pos = strstr(temp, "id");
        if (!pos) pos = strstr(temp, "7*7");
        if (pos) {
            *pos = '\0';
            snprintf(result, 2048, "%s%s%s", temp, command, pos + (strstr(base_payload, "whoami") ? 6 : (strstr(base_payload, "id") ? 2 : 3)));
        } else {
            snprintf(result, 2048, "%s", base_payload);
        }
        free(temp);
    } else {
        snprintf(result, 2048, "%s", base_payload);
    }
    
    return result;
}

static char* expand_sql_payload(const char* base_payload, const char* vector) {
    char* result = malloc(2048);
    if (!result) return NULL;
    
    // SQL payloads are often complete, just use the vector directly
    snprintf(result, 2048, "%s", vector);
    
    return result;
}

static char* expand_ssrf_payload(const char* base_payload, const char* target_url) {
    char* result = malloc(2048);
    if (!result) return NULL;
    
    if (strstr(base_payload, "169.254.169.254") || strstr(base_payload, "metadata")) {
        char* temp = strdup(base_payload);
        char* pos = strstr(temp, "169.254.169.254");
        if (!pos) pos = strstr(temp, "metadata.google.internal");
        if (pos) {
            *pos = '\0';
            snprintf(result, 2048, "%s%s%s", temp, target_url, pos + strlen(pos));
        } else {
            snprintf(result, 2048, "%s", base_payload);
        }
        free(temp);
    } else {
        snprintf(result, 2048, "%s", target_url);
    }
    
    return result;
}

// ========== Main Payload Expansion Function ==========

static ExpandedPayload* expand_payload_with_wordlists(const Payload* base, int* expanded_count) {
    if (!base) return NULL;
    
    ExpandedPayload* expanded = malloc(sizeof(ExpandedPayload));
    if (!expanded) return NULL;
    
    memcpy(&expanded->base, base, sizeof(Payload));
    expanded->variants = NULL;
    expanded->variant_count = 0;
    
    int capacity = 100;
    expanded->variants = malloc(sizeof(char*) * capacity);
    
    // Add the original payload first
    expanded->variants[expanded->variant_count++] = strdup(base->payload);
    
    // Expand based on category
    if (strcmp(base->category, "command_injection") == 0) {
        int cmd_count = 0;
        char** commands = get_payload_wordlist("unix_commands", &cmd_count);
        
        if (commands && cmd_count > 0) {
            for (int i = 0; i < cmd_count && expanded->variant_count < capacity; i++) {
                char* variant = expand_command_injection_payload(base->payload, commands[i]);
                if (variant) {
                    if (expanded->variant_count >= capacity) {
                        capacity += 100;
                        expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                    }
                    expanded->variants[expanded->variant_count++] = variant;
                }
            }
        }
        
        // Add reverse shells
        int rs_count = 0;
        char** reverse_shells = get_payload_wordlist("reverse_shells", &rs_count);
        if (reverse_shells && rs_count > 0) {
            for (int i = 0; i < rs_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(reverse_shells[i]);
            }
        }
        
        // Add time-based payloads for blind injection
        int tb_count = 0;
        char** time_based = get_payload_wordlist("time_based", &tb_count);
        if (time_based && tb_count > 0) {
            for (int i = 0; i < tb_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(time_based[i]);
            }
        }
    }
    
    else if (strcmp(base->category, "path_traversal") == 0) {
        int path_count = 0;
        char** paths = get_payload_wordlist("linux_paths", &path_count);
        
        if (paths && path_count > 0) {
            for (int i = 0; i < path_count && expanded->variant_count < capacity; i++) {
                char* variant = expand_path_traversal_payload(base->payload, paths[i]);
                if (variant) {
                    if (expanded->variant_count >= capacity) {
                        capacity += 100;
                        expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                    }
                    expanded->variants[expanded->variant_count++] = variant;
                }
            }
        }
        
        // Add bypass pattern variants
        int bypass_count = 0;
        char** bypasses = get_payload_wordlist("traversal_bypass", &bypass_count);
        if (bypasses && bypass_count > 0) {
            for (int i = 0; i < bypass_count && expanded->variant_count < capacity; i++) {
                char* variant = expand_path_traversal_payload(bypasses[i], "/etc/passwd");
                if (variant) {
                    if (expanded->variant_count >= capacity) {
                        capacity += 100;
                        expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                    }
                    expanded->variants[expanded->variant_count++] = variant;
                }
            }
        }
    }
    
    else if (strcmp(base->category, "template_injection") == 0) {
        int cmd_count = 0;
        char** commands = get_payload_wordlist("unix_commands", &cmd_count);
        
        if (commands && cmd_count > 0) {
            for (int i = 0; i < cmd_count && i < 10 && expanded->variant_count < capacity; i++) {
                char* variant = expand_template_injection_payload(base->payload, commands[i]);
                if (variant) {
                    if (expanded->variant_count >= capacity) {
                        capacity += 100;
                        expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                    }
                    expanded->variants[expanded->variant_count++] = variant;
                }
            }
        }
        
        // Add Jinja2 vectors
        int jinja_count = 0;
        char** jinja = get_payload_wordlist("jinja2_vectors", &jinja_count);
        if (jinja && jinja_count > 0) {
            for (int i = 0; i < jinja_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(jinja[i]);
            }
        }
    }
    
    else if (strcmp(base->category, "sql_injection") == 0) {
        int mysql_count = 0;
        char** mysql = get_payload_wordlist("mysql_vectors", &mysql_count);
        if (mysql && mysql_count > 0) {
            for (int i = 0; i < mysql_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(mysql[i]);
            }
        }
        
        int union_count = 0;
        char** unions = get_payload_wordlist("union_selects", &union_count);
        if (unions && union_count > 0) {
            for (int i = 0; i < union_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(unions[i]);
            }
        }
        
        int blind_count = 0;
        char** blind = get_payload_wordlist("blind_time", &blind_count);
        if (blind && blind_count > 0) {
            for (int i = 0; i < blind_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(blind[i]);
            }
        }
    }
    
    else if (strcmp(base->category, "ssrf") == 0) {
        int metadata_count = 0;
        char** metadata = get_payload_wordlist("cloud_metadata", &metadata_count);
        if (metadata && metadata_count > 0) {
            for (int i = 0; i < metadata_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(metadata[i]);
            }
        }
        
        int internal_count = 0;
        char** internal = get_payload_wordlist("internal_services", &internal_count);
        if (internal && internal_count > 0) {
            for (int i = 0; i < internal_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(internal[i]);
            }
        }
    }
    
    else if (strcmp(base->category, "nosql_injection") == 0) {
        int mongo_count = 0;
        char** mongo = get_payload_wordlist("mongodb_vectors", &mongo_count);
        if (mongo && mongo_count > 0) {
            for (int i = 0; i < mongo_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(mongo[i]);
            }
        }
    }
    
    else if (strcmp(base->category, "ldap_injection") == 0) {
        int ldap_count = 0;
        char** ldap = get_payload_wordlist("ldap_bypass", &ldap_count);
        if (ldap && ldap_count > 0) {
            for (int i = 0; i < ldap_count && expanded->variant_count < capacity; i++) {
                if (expanded->variant_count >= capacity) {
                    capacity += 100;
                    expanded->variants = realloc(expanded->variants, sizeof(char*) * capacity);
                }
                expanded->variants[expanded->variant_count++] = strdup(ldap[i]);
            }
        }
    }
    
    *expanded_count = expanded->variant_count;
    return expanded;
}

// ========== Load Payloads from JSON and Expand ==========

Payload* load_payloads(const char* path, int* count) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[!] Cannot open payload file: %s\n", path);
        *count = 0;
        return NULL;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char* json_str = malloc(fsize + 1);
    fread(json_str, 1, fsize, fp);
    json_str[fsize] = '\0';
    fclose(fp);
    
    struct json_object* root = json_tokener_parse(json_str);
    free(json_str);
    
    if (!root) {
        fprintf(stderr, "[!] Invalid JSON in payload file\n");
        *count = 0;
        return NULL;
    }
    
    struct json_object* payloads_array;
    if (!json_object_object_get_ex(root, "payloads", &payloads_array)) {
        fprintf(stderr, "[!] No 'payloads' key in JSON\n");
        json_object_put(root);
        *count = 0;
        return NULL;
    }
    
    int len = json_object_array_length(payloads_array);
    
    // First, expand all payloads with wordlists
    Payload* temp_payloads = malloc(sizeof(Payload) * len);
    for (int i = 0; i < len; i++) {
        struct json_object* p = json_object_array_get_idx(payloads_array, i);
        struct json_object* tmp;
        
        memset(&temp_payloads[i], 0, sizeof(Payload));
        
        if (json_object_object_get_ex(p, "id", &tmp))
            strncpy(temp_payloads[i].id, json_object_get_string(tmp), sizeof(temp_payloads[i].id) - 1);
        if (json_object_object_get_ex(p, "name", &tmp))
            strncpy(temp_payloads[i].name, json_object_get_string(tmp), sizeof(temp_payloads[i].name) - 1);
        if (json_object_object_get_ex(p, "category", &tmp))
            strncpy(temp_payloads[i].category, json_object_get_string(tmp), sizeof(temp_payloads[i].category) - 1);
        if (json_object_object_get_ex(p, "subcategory", &tmp))
            strncpy(temp_payloads[i].subcategory, json_object_get_string(tmp), sizeof(temp_payloads[i].subcategory) - 1);
        if (json_object_object_get_ex(p, "payload", &tmp))
            strncpy(temp_payloads[i].payload, json_object_get_string(tmp), sizeof(temp_payloads[i].payload) - 1);
        
        const char* sev_str = "";
        if (json_object_object_get_ex(p, "severity", &tmp))
            sev_str = json_object_get_string(tmp);
        if (strcmp(sev_str, "critical") == 0) temp_payloads[i].severity = SEV_CRITICAL;
        else if (strcmp(sev_str, "high") == 0) temp_payloads[i].severity = SEV_HIGH;
        else if (strcmp(sev_str, "medium") == 0) temp_payloads[i].severity = SEV_MEDIUM;
        else temp_payloads[i].severity = SEV_INFO;
        
        if (json_object_object_get_ex(p, "cve_id", &tmp))
            strncpy(temp_payloads[i].cve_id, json_object_get_string(tmp), sizeof(temp_payloads[i].cve_id) - 1);
        
        if (json_object_object_get_ex(p, "detection_indicators", &tmp) && json_object_is_type(tmp, json_type_array)) {
            int ind_count = json_object_array_length(tmp);
            temp_payloads[i].indicator_count = ind_count > 16 ? 16 : ind_count;
            for (int j = 0; j < temp_payloads[i].indicator_count; j++) {
                struct json_object* ind = json_object_array_get_idx(tmp, j);
                strncpy(temp_payloads[i].detection_indicators[j], 
                        json_object_get_string(ind), 
                        sizeof(temp_payloads[i].detection_indicators[j]) - 1);
            }
        }
    }
    
    // Expand each payload with wordlists
    g_expanded_payloads = malloc(sizeof(ExpandedPayload) * len);
    g_expanded_payload_count = 0;
    
    for (int i = 0; i < len; i++) {
        int variant_count = 0;
        ExpandedPayload* expanded = expand_payload_with_wordlists(&temp_payloads[i], &variant_count);
        if (expanded && variant_count > 0) {
            g_expanded_payloads[g_expanded_payload_count++] = *expanded;
            free(expanded);
        }
    }
    
    // Flatten expanded payloads into single array for scanner
    int total_variants = 0;
    for (int i = 0; i < g_expanded_payload_count; i++) {
        total_variants += g_expanded_payloads[i].variant_count;
    }
    
    Payload* all_payloads = malloc(sizeof(Payload) * total_variants);
    int idx = 0;
    
    for (int i = 0; i < g_expanded_payload_count; i++) {
        for (int j = 0; j < g_expanded_payloads[i].variant_count; j++) {
            memcpy(&all_payloads[idx], &g_expanded_payloads[i].base, sizeof(Payload));
            strncpy(all_payloads[idx].payload, g_expanded_payloads[i].variants[j], sizeof(all_payloads[idx].payload) - 1);
            
            // Append variant ID to the payload ID for tracking
            char variant_id[64];
            snprintf(variant_id, sizeof(variant_id), "%s-V%d", all_payloads[idx].id, j + 1);
            strncpy(all_payloads[idx].id, variant_id, sizeof(all_payloads[idx].id) - 1);
            
            idx++;
        }
    }
    
    json_object_put(root);
    free(temp_payloads);
    *count = total_variants;
    
    log_info("Payload expansion complete: %d base payloads → %d variants", len, total_variants);
    
    return all_payloads;
}

// ========== Filter Functions ==========

void filter_payloads_by_category(Payload** payloads, int* count, const char* category) {
    if (!payloads || !*payloads || *count == 0 || !category) return;
    
    Payload* filtered = malloc(sizeof(Payload) * (*count));
    int filtered_count = 0;
    
    for (int i = 0; i < *count; i++) {
        if (strcmp((*payloads)[i].category, category) == 0) {
            filtered[filtered_count++] = (*payloads)[i];
        }
    }
    
    if (filtered_count > 0) {
        free(*payloads);
        *payloads = filtered;
        *count = filtered_count;
    } else {
        free(filtered);
    }
}

void filter_payloads_by_severity(Payload** payloads, int* count, Severity min_sev) {
    if (!payloads || !*payloads || *count == 0) return;
    
    Payload* filtered = malloc(sizeof(Payload) * (*count));
    int filtered_count = 0;
    
    for (int i = 0; i < *count; i++) {
        if ((*payloads)[i].severity >= min_sev) {
            filtered[filtered_count++] = (*payloads)[i];
        }
    }
    
    if (filtered_count > 0) {
        free(*payloads);
        *payloads = filtered;
        *count = filtered_count;
    } else {
        free(filtered);
    }
}

// ========== Free Payloads ==========

void free_payloads(Payload* payloads, int count) {
    if (payloads) {
        free(payloads);
    }
    
    // Free expanded payload variants
    for (int i = 0; i < g_expanded_payload_count; i++) {
        for (int j = 0; j < g_expanded_payloads[i].variant_count; j++) {
            free(g_expanded_payloads[i].variants[j]);
        }
        free(g_expanded_payloads[i].variants);
    }
    free(g_expanded_payloads);
    g_expanded_payloads = NULL;
    g_expanded_payload_count = 0;
}

// ========== Print Payload Summary ==========

void print_payload_summary(Payload* payloads, int count) {
    if (!payloads || count == 0) {
        printf("[*] No payloads loaded\n");
        return;
    }
    
    printf("\n[*] Payload Summary:\n");
    printf("    Total: %d payloads (expanded from wordlists)\n", count);
    
    // Count by category
    char categories[20][64];
    int category_counts[20] = {0};
    int cat_count = 0;
    
    for (int i = 0; i < count; i++) {
        int found = 0;
        for (int j = 0; j < cat_count; j++) {
            if (strcmp(categories[j], payloads[i].category) == 0) {
                category_counts[j]++;
                found = 1;
                break;
            }
        }
        if (!found && cat_count < 20) {
            strcpy(categories[cat_count], payloads[i].category);
            category_counts[cat_count]++;
            cat_count++;
        }
    }
    
    for (int i = 0; i < cat_count; i++) {
        printf("    - %s: %d\n", categories[i], category_counts[i]);
    }
    
    // Count by severity
    int sev_counts[5] = {0};
    for (int i = 0; i < count; i++) {
        sev_counts[payloads[i].severity]++;
    }
    
    printf("\n[*] By Severity:\n");
    printf("    - CRITICAL: %d\n", sev_counts[SEV_CRITICAL]);
    printf("    - HIGH: %d\n", sev_counts[SEV_HIGH]);
    printf("    - MEDIUM: %d\n", sev_counts[SEV_MEDIUM]);
    printf("    - LOW: %d\n", sev_counts[SEV_LOW]);
    printf("    - INFO: %d\n", sev_counts[SEV_INFO]);
}

// ========== Reload All Wordlists ==========

void reload_payload_wordlists(void) {
    for (int i = 0; i < g_payload_wordlist_count; i++) {
        free(g_payload_wordlists[i].name);
        free_payload_wordlist(g_payload_wordlists[i].entries, g_payload_wordlists[i].count);
    }
    g_payload_wordlist_count = 0;
    g_payload_wordlists_loaded = 0;
    
    load_all_payload_wordlists();
    log_info("Payload wordlists reloaded");
}