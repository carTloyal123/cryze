// android_stubs.c — Bionic libc shims for loading Android .so files on musl/glibc.
// Linked statically; -rdynamic exports symbols for the SDK's dynamic resolver.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum {
    ANDROID_LOG_VERBOSE = 2, ANDROID_LOG_DEBUG, ANDROID_LOG_INFO,
    ANDROID_LOG_WARN, ANDROID_LOG_ERROR, ANDROID_LOG_FATAL,
};

static const char *prio_str(int p) {
    switch (p) {
        case ANDROID_LOG_VERBOSE: return "V";
        case ANDROID_LOG_DEBUG:   return "D";
        case ANDROID_LOG_INFO:    return "I";
        case ANDROID_LOG_WARN:    return "W";
        case ANDROID_LOG_ERROR:   return "E";
        case ANDROID_LOG_FATAL:   return "F";
        default:                  return "?";
    }
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = fprintf(stderr, "[android:%s %s] ", prio_str(prio), tag ? tag : "-");
    n += vfprintf(stderr, fmt, ap);
    va_end(ap);
    size_t L = fmt ? strlen(fmt) : 0;
    if (L == 0 || fmt[L - 1] != '\n') fputc('\n', stderr);
    return n;
}

int *__errno(void) { return __errno_location(); }

size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t n = (srclen < size - 1) ? srclen : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return srclen;
}

#include <stdint.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

static void _fill_rand(void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            FILE *f = fopen("/dev/urandom", "rb");
            if (f) { fread(p, 1, n, f); fclose(f); }
            return;
        }
        p += r;
        n -= r;
    }
}

uint32_t arc4random(void) {
    uint32_t v;
    _fill_rand(&v, sizeof(v));
    return v;
}

void arc4random_buf(void *buf, size_t n) {
    _fill_rand(buf, n);
}

#include <stdlib.h>
#include <locale.h>

int __vsnprintf_chk(char *s, size_t n, int flags, size_t bos,
                    const char *fmt, va_list ap) {
    (void)flags; (void)bos;
    return vsnprintf(s, n, fmt, ap);
}
int __snprintf_chk(char *s, size_t n, int flags, size_t bos,
                   const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = vsnprintf(s, n, fmt, ap);
    va_end(ap);
    (void)flags; (void)bos;
    return r;
}

size_t __strlen_chk(const char *s, size_t bos) { (void)bos; return strlen(s); }
char  *__strcpy_chk(char *dst, const char *src, size_t bos) { (void)bos; return strcpy(dst, src); }
char  *__strcat_chk(char *dst, const char *src, size_t bos) { (void)bos; return strcat(dst, src); }
void  *__memcpy_chk(void *d, const void *s, size_t n, size_t bos) { (void)bos; return memcpy(d, s, n); }
void  *__memmove_chk(void *d, const void *s, size_t n, size_t bos) { (void)bos; return memmove(d, s, n); }
void  *__memset_chk(void *d, int c, size_t n, size_t bos) { (void)bos; return memset(d, c, n); }
char  *__strncpy_chk(char *dst, const char *src, size_t n, size_t bos) { (void)bos; return strncpy(dst, src, n); }
char  *__strncpy_chk2(char *dst, const char *src, size_t n, size_t bos, size_t bos_src) { (void)bos; (void)bos_src; return strncpy(dst, src, n); }
size_t __fread_chk(void *p, size_t sz, size_t nm, FILE *f, size_t bos) { (void)bos; return fread(p, sz, nm, f); }
size_t __fwrite_chk(const void *p, size_t sz, size_t nm, FILE *f, size_t bos) { (void)bos; return fwrite(p, sz, nm, f); }
ssize_t __read_chk(int fd, void *buf, size_t count, size_t bos) { (void)bos; return read(fd, buf, count); }
int __sprintf_chk(char *s, int flags, size_t bos, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = vsprintf(s, fmt, ap);
    va_end(ap);
    (void)flags; (void)bos;
    return r;
}
int __vsprintf_chk(char *s, int flags, size_t bos, const char *fmt, va_list ap) {
    (void)flags; (void)bos;
    return vsprintf(s, fmt, ap);
}

// Bionic _ctype_ table for inline ctype macros.
#include <ctype.h>
unsigned char _ctype_[257];
__attribute__((constructor)) static void _init_ctype(void) {
    unsigned char *t = (unsigned char *)_ctype_ + 1;
    for (int c = 0; c < 256; ++c) {
        unsigned char f = 0;
        if (isupper(c)) f |= 0x01;
        if (islower(c)) f |= 0x02;
        if (isdigit(c)) f |= 0x04;
        if (isspace(c)) f |= 0x08;
        if (ispunct(c)) f |= 0x10;
        if (iscntrl(c)) f |= 0x20;
        if (isxdigit(c)) f |= 0x40;
        if (c == ' ')   f |= 0x80;
        t[c] = f;
    }
}

long long strtoll_l(const char *s, char **end, int base, locale_t loc) {
    (void)loc; return strtoll(s, end, base);
}
unsigned long long strtoull_l(const char *s, char **end, int base, locale_t loc) {
    (void)loc; return strtoull(s, end, base);
}

void android_set_abort_message(const char *msg) {
    fprintf(stderr, "[android-abort] %s\n", msg ? msg : "(null)");
}
int __system_property_get(const char *name, char *value) {
    if (value) value[0] = '\0';
    (void)name;
    return 0;
}

// Bionic pthread cleanup stubs (no-op; we never cancel SDK threads).
void __pthread_cleanup_push(void *r, void (*fn)(void*), void *arg) {
    (void)r; (void)fn; (void)arg;
}
void __pthread_cleanup_pop(void *r, int execute) {
    (void)r; (void)execute;
}

int __android_log_write(int prio, const char *tag, const char *msg) {
    return fprintf(stderr, "[android:%s %s] %s\n", prio_str(prio),
                   tag ? tag : "-", msg ? msg : "");
}
int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap) {
    int n = fprintf(stderr, "[android:%s %s] ", prio_str(prio), tag ? tag : "-");
    n += vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    return n;
}
void __android_log_assert(const char *cond, const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[android:F %s] ASSERT %s ", tag ? tag : "-",
            cond ? cond : "");
    vfprintf(stderr, fmt ? fmt : "", ap);
    fputc('\n', stderr);
    va_end(ap);
    abort();
}

#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
int __open_2(const char *path, int flags) { return open(path, flags); }
int __FD_SET_chk(int fd, fd_set *s, size_t setsize) { (void)setsize; FD_SET(fd, s); return 0; }
ssize_t __write_chk(int fd, const void *buf, size_t count, size_t bos) { (void)bos; return write(fd, buf, count); }
ssize_t __sendto_chk(int fd, const void *buf, size_t len, size_t bos, int flags,
                     const struct sockaddr *to, socklen_t tolen) {
    (void)bos;
    return sendto(fd, buf, len, flags, to, tolen);
}
char *__strchr_chk(const char *s, int c, size_t bos) { (void)bos; return strchr((char*)s, c); }
char *__strrchr_chk(const char *s, int c, size_t bos) { (void)bos; return strrchr((char*)s, c); }
int __get_h_errno(void) { return 0; }

// No-op atfork (never fork after dlopen).
int __register_atfork(void (*prepare)(void), void (*parent)(void),
                      void (*child)(void), void *dso_handle) {
    (void)prepare; (void)parent; (void)child; (void)dso_handle;
    return 0;
}
