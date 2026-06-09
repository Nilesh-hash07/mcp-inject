#include "mcp-inject.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// ========== Base64 Encoding ==========

char* base64_encode(const unsigned char* input, int length) {
    if (!input || length <= 0) return NULL;
    
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char* output = malloc(buffer_ptr->length + 1);
    if (output) {
        memcpy(output, buffer_ptr->data, buffer_ptr->length);
        output[buffer_ptr->length] = '\0';
    }
    
    BIO_free_all(bio);
    
    return output;
}

// ========== Base64 Decoding ==========

unsigned char* base64_decode(const char* input, int* out_len) {
    if (!input) return NULL;
    
    BIO *bio, *b64;
    int decode_len = strlen(input);
    unsigned char* buffer = malloc(decode_len);
    if (!buffer) return NULL;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, buffer, decode_len);
    
    BIO_free_all(bio);
    
    return buffer;
}

// ========== URL Encoding ==========

char* url_encode(const char* input) {
    if (!input) return NULL;
    
    int len = strlen(input);
    char* output = malloc(len * 3 + 1);
    if (!output) return NULL;
    
    int j = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = input[i];
        
        // Unreserved characters per RFC 3986
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            output[j++] = c;
        } else {
            output[j++] = '%';
            output[j++] = "0123456789ABCDEF"[c >> 4];
            output[j++] = "0123456789ABCDEF"[c & 15];
        }
    }
    output[j] = '\0';
    
    return output;
}

// ========== URL Decoding ==========

char* url_decode(const char* input) {
    if (!input) return NULL;
    
    int len = strlen(input);
    char* output = malloc(len + 1);
    if (!output) return NULL;
    
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (input[i] == '%' && i + 2 < len) {
            char hex[3] = {input[i + 1], input[i + 2], '\0'};
            output[j++] = strtol(hex, NULL, 16);
            i += 2;
        } else if (input[i] == '+') {
            output[j++] = ' ';
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    return output;
}

// ========== Hex Encoding ==========

char* hex_encode(const unsigned char* input, int length) {
    if (!input || length <= 0) return NULL;
    
    char* output = malloc(length * 2 + 1);
    if (!output) return NULL;
    
    for (int i = 0; i < length; i++) {
        output[i * 2] = "0123456789abcdef"[input[i] >> 4];
        output[i * 2 + 1] = "0123456789abcdef"[input[i] & 0x0f];
    }
    output[length * 2] = '\0';
    
    return output;
}

// ========== Hex Decoding ==========

unsigned char* hex_decode(const char* input, int* out_len) {
    if (!input) return NULL;
    
    int len = strlen(input);
    if (len % 2 != 0) return NULL;
    
    *out_len = len / 2;
    unsigned char* output = malloc(*out_len);
    if (!output) return NULL;
    
    for (int i = 0; i < *out_len; i++) {
        char byte_str[3] = {input[i * 2], input[i * 2 + 1], '\0'};
        output[i] = strtol(byte_str, NULL, 16);
    }
    
    return output;
}

// ========== Double URL Encoding ==========

char* double_url_encode(const char* input) {
    if (!input) return NULL;
    
    char* first_pass = url_encode(input);
    if (!first_pass) return NULL;
    
    char* second_pass = url_encode(first_pass);
    free(first_pass);
    
    return second_pass;
}

// ========== MD5 Hash ==========

char* md5_hash(const char* input) {
    if (!input) return NULL;
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input, strlen(input), digest);
    
    char* output = malloc(MD5_DIGEST_LENGTH * 2 + 1);
    if (!output) return NULL;
    
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[MD5_DIGEST_LENGTH * 2] = '\0';
    
    return output;
}

// ========== SHA256 Hash ==========

char* sha256_hash(const char* input) {
    if (!input) return NULL;
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), digest);
    
    char* output = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!output) return NULL;
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    return output;
}

// ========== Random String Generation ==========

char* random_string(int length) {
    if (length <= 0) return NULL;
    
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int charset_size = sizeof(charset) - 1;
    
    char* output = malloc(length + 1);
    if (!output) return NULL;
    
    srand(time(NULL) ^ (rand() << 16));
    
    for (int i = 0; i < length; i++) {
        output[i] = charset[rand() % charset_size];
    }
    output[length] = '\0';
    
    return output;
}

// ========== XOR Encryption (Simple Payload Obfuscation) ==========

char* xor_encrypt(const char* input, char key) {
    if (!input) return NULL;
    
    int len = strlen(input);
    char* output = malloc(len + 1);
    if (!output) return NULL;
    
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ key;
    }
    output[len] = '\0';
    
    return output;
}

// ========== Caesar Cipher (Simple Payload Obfuscation) ==========

char* caesar_cipher(const char* input, int shift) {
    if (!input) return NULL;
    
    int len = strlen(input);
    char* output = malloc(len + 1);
    if (!output) return NULL;
    
    shift = shift % 26;
    
    for (int i = 0; i < len; i++) {
        char c = input[i];
        if (isupper(c)) {
            output[i] = ((c - 'A' + shift) % 26) + 'A';
        } else if (islower(c)) {
            output[i] = ((c - 'a' + shift) % 26) + 'a';
        } else {
            output[i] = c;
        }
    }
    output[len] = '\0';
    
    return output;
}

// ========== Reverse String ==========

char* reverse_string(const char* input) {
    if (!input) return NULL;
    
    int len = strlen(input);
    char* output = malloc(len + 1);
    if (!output) return NULL;
    
    for (int i = 0; i < len; i++) {
        output[i] = input[len - 1 - i];
    }
    output[len] = '\0';
    
    return output;
}

// ========== Payload Encoding Dispatcher ==========

char* encode_payload(const char* payload, int encoding_type) {
    if (!payload) return NULL;
    
    switch (encoding_type) {
        case 0:
            return strdup(payload);
        case 1:
            return base64_encode((unsigned char*)payload, strlen(payload));
        case 2:
            return hex_encode((unsigned char*)payload, strlen(payload));
        case 3:
            return url_encode(payload);
        case 4:
            return double_url_encode(payload);
        case 5:
            return xor_encrypt(payload, 0x42);
        case 6:
            return caesar_cipher(payload, 13);
        case 7:
            return reverse_string(payload);
        default:
            return strdup(payload);
    }
}

// ========== Generate Boundary for Multipart ==========

char* generate_boundary(void) {
    return random_string(16);
}

// ========== Obfuscate SQL Keyword ==========

char* obfuscate_sql_keyword(const char* keyword) {
    if (!keyword) return NULL;
    
    char* result = malloc(strlen(keyword) * 4 + 1);
    if (!result) return NULL;
    
    result[0] = '\0';
    for (int i = 0; i < strlen(keyword); i++) {
        char c = keyword[i];
        if (rand() % 2) {
            char obf[16];
            snprintf(obf, sizeof(obf), "/*!%c*/", c);
            strcat(result, obf);
        } else {
            char obf[16];
            snprintf(obf, sizeof(obf), "%c", c);
            strcat(result, obf);
        }
    }
    
    return result;
}