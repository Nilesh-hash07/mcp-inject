#include "mcp-inject.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

typedef struct {
    char* name;
    char** entries;
    int count;
} EvasionWordlist;

static EvasionWordlist g_evasion_wordlists[20];
static int g_evasion_wordlist_count = 0;
static int g_evasion_wordlists_loaded = 0;

static char** load_evasion_wordlist(const char* path, int* count) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        *count = 0;
        return NULL;
    }
    
    char** lines = malloc(sizeof(char*) * 2000);
    int capacity = 2000;
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

static void free_evasion_wordlist(char** entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) free(entries[i]);
    free(entries);
}

static void load_all_evasion_wordlists(void) {
    if (g_evasion_wordlists_loaded) return;
    
    struct {
        const char* name;
        const char* path;
    } wordlist_defs[] = {
        {"user_agents", "config/wordlists/user_agents/browsers.txt"},
        {"whitespace", "config/wordlists/evasion/whitespace.txt"},
        {"case_variations", "config/wordlists/evasion/case_variations.txt"}
    };
    int num_defs = sizeof(wordlist_defs) / sizeof(wordlist_defs[0]);
    
    for (int i = 0; i < num_defs && g_evasion_wordlist_count < 20; i++) {
        int count = 0;
        char** entries = load_evasion_wordlist(wordlist_defs[i].path, &count);
        
        if (entries && count > 0) {
            g_evasion_wordlists[g_evasion_wordlist_count].name = strdup(wordlist_defs[i].name);
            g_evasion_wordlists[g_evasion_wordlist_count].entries = entries;
            g_evasion_wordlists[g_evasion_wordlist_count].count = count;
            g_evasion_wordlist_count++;
            log_info("Evasion: Loaded %d entries from %s", count, wordlist_defs[i].path);
        }
    }
    
    g_evasion_wordlists_loaded = 1;
}

static char** get_evasion_wordlist(const char* name, int* count) {
    if (!g_evasion_wordlists_loaded) load_all_evasion_wordlists();
    
    for (int i = 0; i < g_evasion_wordlist_count; i++) {
        if (strcmp(g_evasion_wordlists[i].name, name) == 0) {
            *count = g_evasion_wordlists[i].count;
            return g_evasion_wordlists[i].entries;
        }
    }
    *count = 0;
    return NULL;
}

static void apply_case_variation(char* payload, size_t size) {
    (void)size;
    for (char* p = payload; *p; p++) {
        if (isalpha(*p)) {
            if (rand() % 2) *p = toupper(*p);
            else *p = tolower(*p);
        }
    }
}

static void apply_whitespace_variation(char* payload, size_t size) {
    char* result = malloc(size * 2);
    if (!result) return;
    result[0] = '\0';
    
    for (char* p = payload; *p; p++) {
        if (*p == ' ') {
            strcat(result, "%20");
        } else {
            char single[2] = {*p, '\0'};
            strcat(result, single);
        }
    }
    strncpy(payload, result, size);
    free(result);
}

void apply_evasion(char* payload, size_t size) {
    if (!payload || size == 0) return;
    srand(time(NULL) ^ (getpid() << 16));
    
    int technique = rand() % 2;
    switch (technique) {
        case 0: apply_case_variation(payload, size); break;
        case 1: apply_whitespace_variation(payload, size); break;
    }
}

char* get_random_user_agent(void) {
    int ua_count = 0;
    char** user_agents = get_evasion_wordlist("user_agents", &ua_count);
    
    if (ua_count > 0 && user_agents) {
        int idx = rand() % ua_count;
        return strdup(user_agents[idx]);
    }
    
    const char* fallback = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    return strdup(fallback);
}

int random_delay_ms(int min_ms, int max_ms) {
    if (min_ms >= max_ms) return min_ms;
    srand(time(NULL) ^ (rand() << 16));
    return min_ms + (rand() % (max_ms - min_ms));
}

void reload_evasion_wordlists(void) {
    for (int i = 0; i < g_evasion_wordlist_count; i++) {
        free(g_evasion_wordlists[i].name);
        free_evasion_wordlist(g_evasion_wordlists[i].entries, g_evasion_wordlists[i].count);
    }
    g_evasion_wordlist_count = 0;
    g_evasion_wordlists_loaded = 0;
    load_all_evasion_wordlists();
    log_info("Evasion wordlists reloaded");
}