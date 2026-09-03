/* tutil.h — tiny hex / line helpers shared by the test programs. */
#ifndef TUTIL_H
#define TUTIL_H
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void hex_enc(const uint8_t* in, size_t n, char* out) {
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 15]; }
    out[2*n] = 0;
}

static int hex_nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns 1 on success (exactly n bytes decoded). */
static int hex_dec(const char* s, uint8_t* out, size_t n) {
    if (strlen(s) != 2*n) return 0;
    for (size_t i = 0; i < n; i++) {
        int h = hex_nib(s[2*i]), l = hex_nib(s[2*i+1]);
        if (h < 0 || l < 0) return 0;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return 1;
}

/* K12 spec pattern: bytes 00..FA repeated, truncated to n. */
static void ptn(uint8_t* out, size_t n) { for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(i % 251); }

/* Reads next non-comment, non-empty line (trailing newline stripped). */
static int next_line(FILE* f, char* buf, size_t cap) {
    while (fgets(buf, (int)cap, f)) {
        size_t n = strlen(buf);
        while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = 0;
        if (n == 0 || buf[0] == '#') continue;
        return 1;
    }
    return 0;
}
#endif
