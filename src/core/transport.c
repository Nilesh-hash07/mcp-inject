#include "mcp-inject.h"
#include <curl/curl.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char* memory;
    size_t size;
} TransportChunk;

static size_t transport_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    TransportChunk* chunk = (TransportChunk*)userp;
    
    char* ptr = realloc(chunk->memory, chunk->size + realsize + 1);
    if (!ptr) return 0;
    
    chunk->memory = ptr;
    memcpy(&(chunk->memory[chunk->size]), contents, realsize);
    chunk->size += realsize;
    chunk->memory[chunk->size] = '\0';
    
    return realsize;
}

static int transport_http_send(TargetConfig* config, const char* json_body, char** response) {
    CURL* curl = curl_easy_init();
    if (!curl) return -1;
    
    TransportChunk chunk = {0};
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    char ua_header[512];
    if (config->user_agent[0]) {
        snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", config->user_agent);
        headers = curl_slist_append(headers, ua_header);
    }
    
    char url[1024];
    snprintf(url, sizeof(url), "%s/mcp", config->url);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, transport_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout_sec);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    if (config->proxy[0]) {
        curl_easy_setopt(curl, CURLOPT_PROXY, config->proxy);
    }
    
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    
    int success = -1;
    if (res == CURLE_OK && chunk.memory && chunk.size > 0) {
        *response = chunk.memory;
        success = 0;
    } else {
        if (chunk.memory) free(chunk.memory);
        *response = NULL;
        log_error("HTTP request failed: %s", curl_easy_strerror(res));
    }
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    
    return success;
}

static int transport_websocket_send(TargetConfig* config, const char* json_body, char** response) {
    (void)config;
    (void)json_body;
    (void)response;
    log_error("WebSocket support not compiled (requires libwebsockets)");
    return -1;
}

static int transport_stdio_send(TargetConfig* config, const char* json_body, char** response) {
    (void)config;
    FILE* pipe = popen(json_body, "r");
    if (!pipe) {
        log_error("STDIO pipe failed");
        return -1;
    }
    
    char* result = malloc(MAX_RESPONSE_SIZE);
    if (!result) {
        pclose(pipe);
        return -1;
    }
    
    size_t total = 0;
    while (fgets(result + total, MAX_RESPONSE_SIZE - total, pipe)) {
        total = strlen(result);
        if (total >= MAX_RESPONSE_SIZE - 1024) break;
    }
    
    pclose(pipe);
    
    if (total > 0) {
        *response = result;
        return 0;
    }
    
    free(result);
    return -1;
}

static int transport_sse_send(TargetConfig* config, const char* json_body, char** response) {
    char url[1024];
    snprintf(url, sizeof(url), "%s/sse", config->url);
    
    CURL* curl = curl_easy_init();
    if (!curl) return -1;
    
    TransportChunk chunk = {0};
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: text/event-stream");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, transport_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout_sec);
    
    if (config->proxy[0]) {
        curl_easy_setopt(curl, CURLOPT_PROXY, config->proxy);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    int success = -1;
    if (res == CURLE_OK && chunk.memory && chunk.size > 0) {
        *response = chunk.memory;
        success = 0;
    } else {
        if (chunk.memory) free(chunk.memory);
        *response = NULL;
    }
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    
    return success;
}

int transport_send(TargetConfig* config, const char* json_body, char** response) {
    if (!config || !json_body || !response) return -1;
    
    switch (config->transport) {
        case TRANSPORT_HTTP:
            return transport_http_send(config, json_body, response);
        case TRANSPORT_WEBSOCKET:
            return transport_websocket_send(config, json_body, response);
        case TRANSPORT_STDIO:
            return transport_stdio_send(config, json_body, response);
        case TRANSPORT_SSE:
            return transport_sse_send(config, json_body, response);
        default:
            log_error("Unknown transport type: %d", config->transport);
            return -1;
    }
}

void transport_cleanup(void) {
    curl_global_cleanup();
}

int transport_init(void) {
    curl_global_init(CURL_GLOBAL_ALL);
    return 0;
}