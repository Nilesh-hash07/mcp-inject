#include "mcp-inject.h"
#include <json-c/json.h>
#include <time.h>
#include <ctype.h>

static const char* severity_badge_text(Severity s) {
    switch (s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH: return "HIGH";
        case SEV_MEDIUM: return "MEDIUM";
        case SEV_LOW: return "LOW";
        default: return "INFO";
    }
}

static const char* severity_class(Severity s) {
    switch (s) {
        case SEV_CRITICAL: return "critical";
        case SEV_HIGH: return "high";
        case SEV_MEDIUM: return "medium";
        case SEV_LOW: return "low";
        default: return "info";
    }
}

char* report_to_json(ScannerState* state) {
    if (!state) return strdup("{}");
    
    struct json_object* root = json_object_new_object();
    struct json_object* metadata = json_object_new_object();
    struct json_object* summary = json_object_new_object();
    struct json_object* findings_array = json_object_new_array();
    
    json_object_object_add(metadata, "tool", json_object_new_string("MCP-Inject-Scanner"));
    json_object_object_add(metadata, "version", json_object_new_string(VERSION));
    
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
    json_object_object_add(metadata, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(metadata, "target", json_object_new_string(state->config.url));
    
    json_object_object_add(summary, "total_payloads", json_object_new_int(state->stats.total_payloads));
    json_object_object_add(summary, "vulnerabilities_found", json_object_new_int(state->findings_count));
    json_object_object_add(summary, "scan_duration_seconds", json_object_new_double(state->stats.end_time - state->stats.start_time));
    json_object_object_add(summary, "requests_per_second", json_object_new_double(state->stats.requests_per_second));
    
    int sev_counts[5] = {0};
    for (int i = 0; i < state->findings_count; i++) {
        sev_counts[state->findings[i].severity]++;
    }
    
    struct json_object* severity_breakdown = json_object_new_object();
    json_object_object_add(severity_breakdown, "critical", json_object_new_int(sev_counts[SEV_CRITICAL]));
    json_object_object_add(severity_breakdown, "high", json_object_new_int(sev_counts[SEV_HIGH]));
    json_object_object_add(severity_breakdown, "medium", json_object_new_int(sev_counts[SEV_MEDIUM]));
    json_object_object_add(severity_breakdown, "low", json_object_new_int(sev_counts[SEV_LOW]));
    json_object_object_add(severity_breakdown, "info", json_object_new_int(sev_counts[SEV_INFO]));
    json_object_object_add(summary, "severity_breakdown", severity_breakdown);
    
    for (int i = 0; i < state->findings_count; i++) {
        struct json_object* finding = json_object_new_object();
        
        json_object_object_add(finding, "id", json_object_new_string(state->findings[i].payload_id));
        json_object_object_add(finding, "name", json_object_new_string(state->findings[i].payload_name));
        json_object_object_add(finding, "category", json_object_new_string(state->findings[i].category));
        json_object_object_add(finding, "severity", json_object_new_string(severity_badge_text(state->findings[i].severity)));
        json_object_object_add(finding, "confidence", json_object_new_string(confidence_to_str(state->findings[i].confidence)));
        json_object_object_add(finding, "evidence", json_object_new_string(state->findings[i].evidence));
        json_object_object_add(finding, "response_time_ms", json_object_new_double(state->findings[i].response_time_ms));
        json_object_object_add(finding, "response_size_bytes", json_object_new_int(state->findings[i].response_size));
        
        json_object_array_add(findings_array, finding);
    }
    
    json_object_object_add(root, "metadata", metadata);
    json_object_object_add(root, "summary", summary);
    json_object_object_add(root, "findings", findings_array);
    
    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char* result = strdup(json_str);
    json_object_put(root);
    
    return result;
}

char* report_to_text(ScannerState* state) {
    if (!state) return strdup("No report available");
    
    char* buf = malloc(65536);
    if (!buf) return strdup("Memory allocation failed");
    
    char* ptr = buf;
    int remaining = 65536;
    
    ptr += snprintf(ptr, remaining, 
        "============================================================\n"
        "MCP INJECTION SCAN REPORT\n"
        "============================================================\n\n");
    
    ptr += snprintf(ptr, remaining, "Target: %s\n", state->config.url);
    
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    ptr += snprintf(ptr, remaining, "Scan Time: %s\n\n", timestamp);
    
    ptr += snprintf(ptr, remaining,
        "============================================================\n"
        "SCAN SUMMARY\n"
        "============================================================\n");
    ptr += snprintf(ptr, remaining, "Total Payloads Tested:    %d\n", state->stats.total_payloads);
    ptr += snprintf(ptr, remaining, "Vulnerabilities Found:    %d\n", state->findings_count);
    ptr += snprintf(ptr, remaining, "Scan Duration:            %.2f seconds\n", state->stats.end_time - state->stats.start_time);
    ptr += snprintf(ptr, remaining, "Requests Per Second:      %.2f\n\n", state->stats.requests_per_second);
    
    int sev_counts[5] = {0};
    for (int i = 0; i < state->findings_count; i++) {
        sev_counts[state->findings[i].severity]++;
    }
    
    ptr += snprintf(ptr, remaining,
        "Severity Breakdown:\n"
        "  [CRITICAL]  %d\n"
        "  [HIGH]      %d\n"
        "  [MEDIUM]    %d\n"
        "  [LOW]       %d\n"
        "  [INFO]      %d\n\n",
        sev_counts[SEV_CRITICAL], sev_counts[SEV_HIGH],
        sev_counts[SEV_MEDIUM], sev_counts[SEV_LOW], sev_counts[SEV_INFO]);
    
    if (state->findings_count > 0) {
        ptr += snprintf(ptr, remaining,
            "============================================================\n"
            "VULNERABILITIES FOUND\n"
            "============================================================\n\n");
        
        for (int i = 0; i < state->findings_count; i++) {
            ptr += snprintf(ptr, remaining,
                "[%d] %s (%s)\n", i + 1, state->findings[i].payload_name, state->findings[i].payload_id);
            ptr += snprintf(ptr, remaining, "    Category:   %s\n", state->findings[i].category);
            ptr += snprintf(ptr, remaining, "    Severity:   %s\n", severity_badge_text(state->findings[i].severity));
            ptr += snprintf(ptr, remaining, "    Confidence: %s\n", confidence_to_str(state->findings[i].confidence));
            ptr += snprintf(ptr, remaining, "    Evidence:   %s\n", state->findings[i].evidence);
            ptr += snprintf(ptr, remaining, "    Response:   %.2f ms, %d bytes\n\n",
                state->findings[i].response_time_ms, state->findings[i].response_size);
        }
    } else {
        ptr += snprintf(ptr, remaining,
            "============================================================\n"
            "NO VULNERABILITIES FOUND\n"
            "============================================================\n\n");
    }
    
    return buf;
}

char* report_to_html(ScannerState* state) {
    if (!state) return strdup("<html><body>No report available</body></html>");
    
    char* buf = malloc(256 * 1024);
    if (!buf) return strdup("<html><body>Memory allocation failed</body></html>");
    
    char* ptr = buf;
    int remaining = 256 * 1024;
    
    ptr += snprintf(ptr, remaining,
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "    <meta charset=\"UTF-8\">\n"
        "    <title>MCP Injection Scanner Report</title>\n"
        "    <style>\n"
        "        body { font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }\n"
        "        .container { max-width: 1200px; margin: 0 auto; }\n"
        "        h1 { color: #569cd6; border-bottom: 1px solid #444; }\n"
        "        h2 { color: #ce9178; margin-top: 20px; }\n"
        "        .summary { background: #252526; padding: 15px; border-radius: 5px; margin: 10px 0; }\n"
        "        .finding { background: #2d2d30; padding: 15px; margin: 10px 0; border-left: 4px solid; border-radius: 3px; }\n"
        "        .finding-critical { border-left-color: #dc3545; }\n"
        "        .finding-high { border-left-color: #fd7e14; }\n"
        "        .finding-medium { border-left-color: #ffc107; }\n"
        "        .finding-low { border-left-color: #28a745; }\n"
        "        .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }\n"
        "        .badge-critical { background: #dc3545; color: white; }\n"
        "        .badge-high { background: #fd7e14; color: white; }\n"
        "        .badge-medium { background: #ffc107; color: black; }\n"
        "        .badge-low { background: #28a745; color: white; }\n"
        "        .evidence { background: #1e1e1e; padding: 10px; font-family: monospace; border: 1px solid #444; border-radius: 3px; margin-top: 10px; }\n"
        "        table { width: 100%%; border-collapse: collapse; margin: 10px 0; }\n"
        "        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #444; }\n"
        "        th { background: #252526; color: #569cd6; }\n"
        "        .footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid #444; font-size: 12px; text-align: center; }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "<div class=\"container\">\n");
    
    ptr += snprintf(ptr, remaining, "    <h1>MCP Injection Scanner Report</h1>\n");
    ptr += snprintf(ptr, remaining, "    <p><strong>Target:</strong> %s</p>\n", state->config.url);
    
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    ptr += snprintf(ptr, remaining, "    <p><strong>Scan Time:</strong> %s</p>\n", timestamp);
    
    int sev_counts[5] = {0};
    for (int i = 0; i < state->findings_count; i++) {
        sev_counts[state->findings[i].severity]++;
    }
    
    ptr += snprintf(ptr, remaining,
        "    <div class=\"summary\">\n"
        "        <h2>Summary</h2>\n"
        "        <table>\n"
        "            <tr><th>Total Payloads</th><td>%d</td></tr>\n"
        "            <tr><th>Vulnerabilities Found</th><td><strong>%d</strong></td></tr>\n"
        "            <tr><th>Scan Duration</th><td>%.2f seconds</td></tr>\n"
        "            <tr><th>Requests/Second</th><td>%.2f</td></tr>\n"
        "        </table>\n"
        "    </div>\n",
        state->stats.total_payloads, state->findings_count,
        state->stats.end_time - state->stats.start_time, state->stats.requests_per_second);
    
    ptr += snprintf(ptr, remaining,
        "    <div class=\"summary\">\n"
        "        <h2>Severity Breakdown</h2>\n"
        "        <table>\n"
        "            <tr><th>Critical</th><td><span class=\"badge badge-critical\">%d</span></td></tr>\n"
        "            <tr><th>High</th><td><span class=\"badge badge-high\">%d</span></td></tr>\n"
        "            <tr><th>Medium</th><td><span class=\"badge badge-medium\">%d</span></td></tr>\n"
        "            <tr><th>Low</th><td><span class=\"badge badge-low\">%d</span></td></tr>\n"
        "        </table>\n"
        "    </div>\n",
        sev_counts[SEV_CRITICAL], sev_counts[SEV_HIGH], sev_counts[SEV_MEDIUM], sev_counts[SEV_LOW]);
    
    if (state->findings_count > 0) {
        ptr += snprintf(ptr, remaining, "    <h2>Vulnerabilities Found (%d)</h2>\n", state->findings_count);
        
        for (int i = 0; i < state->findings_count; i++) {
            const char* sev_class = severity_class(state->findings[i].severity);
            const char* sev_text = severity_badge_text(state->findings[i].severity);
            
            ptr += snprintf(ptr, remaining,
                "    <div class=\"finding finding-%s\">\n"
                "        <strong>[%s] %s</strong>\n"
                "        <span class=\"badge badge-%s\" style=\"float: right;\">%s</span><br>\n"
                "        <small>ID: %s | Confidence: %s</small><br>\n"
                "        <div class=\"evidence\">\n"
                "            <strong>Evidence:</strong> %s<br>\n"
                "            <strong>Response Time:</strong> %.2f ms<br>\n"
                "            <strong>Response Size:</strong> %d bytes\n"
                "        </div>\n"
                "    </div>\n",
                sev_class,
                state->findings[i].payload_id, state->findings[i].payload_name,
                sev_class, sev_text,
                state->findings[i].payload_id, confidence_to_str(state->findings[i].confidence),
                state->findings[i].evidence, state->findings[i].response_time_ms, state->findings[i].response_size);
        }
    } else {
        ptr += snprintf(ptr, remaining,
            "    <div class=\"summary\">\n"
            "        <h2>No Vulnerabilities Found</h2>\n"
            "        <p>The target appears to be secure against the tested injection vectors.</p>\n"
            "    </div>\n");
    }
    
    ptr += snprintf(ptr, remaining,
        "    <div class=\"footer\">\n"
        "        Generated by MCP-Inject-Scanner v%s\n"
        "    </div>\n"
        "</div>\n"
        "</body>\n"
        "</html>\n", VERSION);
    
    return buf;
}

void report_save(const char* filename, const char* content) {
    if (!filename || !content) return;
    
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        log_error("Cannot write report to %s", filename);
        return;
    }
    
    fprintf(fp, "%s", content);
    fclose(fp);
    
    log_info("Report saved to %s", filename);
}