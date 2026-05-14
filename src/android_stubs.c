/*
 * android_stubs.c
 *
 * Bionic-libc compatibility shim so that Android-built shared libraries
 * (libiotp2pav.so from the Wyze APK) can be dlopen()ed against glibc.
 *
 * The Tencent IoTVideo P2P core needs four classes of bionic glue:
 *
 *   1. Logging      — __android_log_print  (route to stderr)
 *   2. Errno API    — __errno              (bionic's "get TLS errno *" name;
 *                                           glibc spells it __errno_location)
 *   3. BSD strings  — strlcpy              (BSDism shipped by bionic; glibc
 *                                           on Ubuntu 22.04 lacks it)
 *   4. Stdio        — __sF                 (bionic's stdin/stdout/stderr are
 *                                           macros that take addresses inside
 *                                           an array of 3 FILE objects named
 *                                           __sF. We expose a dummy array and
 *                                           wrap fprintf/fputc/fclose so that
 *                                           any FILE* falling inside __sF gets
 *                                           re-routed to the real glibc stream)
 *
 * Linked into the bridge executable as a static library; -rdynamic exports the
 * symbols so the loader resolves libiotp2pav.so's imports against them.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ logging */

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

/* -------------------------------------------------------------------- errno */

int *__errno(void) { return __errno_location(); }

/* ------------------------------------------------------------------- strlcpy */

size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t n = (srclen < size - 1) ? srclen : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return srclen;
}

/* ------------------------------------------------------------- arc4random */
/*
 * BSD/bionic arc4random API. Added to glibc only in 2.36; Ubuntu 22.04 ships
 * glibc 2.35, so we provide shims backed by getrandom(2).
 */
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
            /* Fallback to /dev/urandom on truly bizarre failure modes. */
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

/* ---------------------------------------------------------------- __sF stdio
 *
 * Bionic exposes stdin/stdout/stderr as macros into an array of 3 FILE objects:
 *     #define stdin   (&__sF[0])
 *     #define stdout  (&__sF[1])
 *     #define stderr  (&__sF[2])
 *
 * The SDK was compiled against bionic. On aarch64-bionic, sizeof(FILE) is 152
 * bytes — confirmed empirically by the SDK's adrp/ldr/add fprintf prep at
 * libiotp2pav.so:0xaf030, which computes &__sF[2] as __sF + 0x130 (= __sF + 304).
 *
 * We expose __sF with slots large enough to cover bionic's layout and translate
 * by RANGE rather than exact pointer match: any address that falls in the first
 * third of our __sF buffer is stdin, second third is stdout, last third is
 * stderr. This is resilient to changes in bionic's sizeof(FILE) between NDK
 * versions and correct as long as bionic's slot size is ≤ kSlotSize.
 *
 * Without range-based translation, `fprintf(stderr, ...)` from the SDK gives us
 * a pointer that doesn't exactly match `&__sF[2]` in our array (different slot
 * stride), so `_translate` returns it unchanged, musl's vfprintf interprets the
 * random memory as a FILE struct, reads function pointers from wrong offsets,
 * gets NULL, and crashes with pc=0 inside vfprintf.
 */
#define SF_SLOT_SIZE 512    /* ≥ both bionic FILE (152B) and any future growth */
typedef struct { char _pad[SF_SLOT_SIZE]; } _bionic_file_slot;
_bionic_file_slot __sF[3];

static int (*real_vfprintf)(FILE *, const char *, va_list);
static int (*real_fputc)(int, FILE *);
static int (*real_fclose)(FILE *);

__attribute__((constructor))
static void _init_libc_passthrough(void) {
    real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    real_fputc    = dlsym(RTLD_NEXT, "fputc");
    real_fclose   = dlsym(RTLD_NEXT, "fclose");
}

/* Returns 0/1/2 for stdin/stdout/stderr if f falls inside our __sF buffer,
 * or -1 if it's a real FILE* from outside. Range-based so we don't depend on
 * bionic's exact sizeof(FILE). */
static int _sf_slot(FILE *f) {
    char *p = (char *)f;
    char *base = (char *)&__sF[0];
    char *end  = base + sizeof(__sF);
    if (p < base || p >= end) return -1;
    size_t off = (size_t)(p - base);
    /* Each slot is SF_SLOT_SIZE bytes from our perspective; bionic's
     * slot stride could be anything ≤ SF_SLOT_SIZE. We just need to know
     * which "third" of the buffer it falls in. */
    if (off < SF_SLOT_SIZE)         return 0;  /* stdin */
    if (off < 2 * SF_SLOT_SIZE)     return 1;  /* stdout */
    return 2;                                  /* stderr */
}

static FILE *_translate(FILE *f) {
    switch (_sf_slot(f)) {
        case 0:  return stdin;
        case 1:  return stdout;
        case 2:  return stderr;
        default: return f;
    }
}
static int _is_dummy(FILE *f) { return _sf_slot(f) >= 0; }

/* These wrappers replace glibc's by name in our process. Probe code that
 * targets real FILE* keeps working because _translate() returns f unchanged. */
int fprintf(FILE *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = real_vfprintf(_translate(f), fmt, ap);
    va_end(ap);
    return r;
}
int vfprintf(FILE *f, const char *fmt, va_list ap) {
    return real_vfprintf(_translate(f), fmt, ap);
}
int fputc(int c, FILE *f) { return real_fputc(c, _translate(f)); }
int fclose(FILE *f) { return _is_dummy(f) ? 0 : real_fclose(f); }

/* ----------------------------------------- additional bionic-only symbols
 * Needed by libgwbase.so / libc++_shared.so / libiotvideo.so. Most are
 * thin shims around their glibc/musl counterparts. */

#include <stdlib.h>
#include <locale.h>

/* FORTIFY: __vsnprintf_chk is bionic's checked vsnprintf. We just ignore
 * the buf-size hint and forward to vsnprintf. */
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

/* More FORTIFY helpers. */
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

/* bionic exposes _ctype_[c]: a 257-element table (one byte per char + sentinel)
 * used by the inline tolower/toupper/isspace etc. macros. musl/glibc don't
 * have it. Build a usable table at startup so SDK code that touches
 * _ctype_[c] gets the right classification flags. Flag bits taken from
 * bionic <ctype.h>: _U=0x01 _L=0x02 _N=0x04 _S=0x08 _P=0x10 _C=0x20 _X=0x40 _B=0x80. */
#include <ctype.h>
const unsigned char _ctype_[257] = {0};
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

/* Locale-aware strtoll/strtoull. We ignore the locale parameter. */
long long strtoll_l(const char *s, char **end, int base, locale_t loc) {
    (void)loc; return strtoll(s, end, base);
}
unsigned long long strtoull_l(const char *s, char **end, int base, locale_t loc) {
    (void)loc; return strtoull(s, end, base);
}

/* bionic-only abort/property APIs — no-op stubs are fine. */
void android_set_abort_message(const char *msg) {
    fprintf(stderr, "[android-abort] %s\n", msg ? msg : "(null)");
}
int __system_property_get(const char *name, char *value) {
    if (value) value[0] = '\0';
    (void)name;
    return 0;
}

/* bionic's pthread cleanup ABI is different from glibc/musl. Provide no-op
 * stubs so the SDK can register/unregister cleanup handlers. These are
 * called by macros expanded inside SDK functions; the real-life behavior
 * is "run handler if thread cancels", but since we never cancel SDK
 * threads, no-ops are safe. */
void __pthread_cleanup_push(void *r, void (*fn)(void*), void *arg) {
    (void)r; (void)fn; (void)arg;
}
void __pthread_cleanup_pop(void *r, int execute) {
    (void)r; (void)execute;
}

/* bionic logging variants. Forward to stderr. */
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

/* Additional bionic-only FORTIFY / FD / file helpers. */
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

/* glibc-private fork helper. musl doesn't export it; provide a no-op (we
 * never fork after dlopen anyway, so cleanup handlers are unused). */
int __register_atfork(void (*prepare)(void), void (*parent)(void),
                      void (*child)(void), void *dso_handle) {
    (void)prepare; (void)parent; (void)child; (void)dso_handle;
    return 0;
}

/* --------------------------------------------------- pthread_create stack
 *
 * The Wyze SDK was compiled targeting bionic, where the default pthread
 * stack is 1 MB. musl's default is 80 KB, which is far too small for the
 * SDK's encode/decode threads — `avctl_start_enc_and_send` does a 141 KB
 * alloca for a raw video frame buffer and crashes (memset SIGSEGV) when
 * it overflows musl's tiny default stack.
 *
 * Interpose pthread_create: if the caller passed no attr or an attr with
 * stacksize < 2 MB, replace with 4 MB. This matches bionic behavior closely
 * enough that all SDK threads have headroom for their internal allocas.
 */
#include <pthread.h>
typedef int (*real_pthread_create_t)(pthread_t *, const pthread_attr_t *,
                                     void *(*)(void *), void *);
static real_pthread_create_t real_pthread_create;
__attribute__((constructor))
static void _init_pthread_passthrough(void) {
    real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
}

int pthread_create(pthread_t *t, const pthread_attr_t *a,
                   void *(*fn)(void *), void *arg) {
    if (!real_pthread_create) {
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    }
    pthread_attr_t my;
    pthread_attr_init(&my);
    if (a) {
        size_t sz = 0;
        pthread_attr_getstacksize((pthread_attr_t *)a, &sz);
        /* Copy detach state from caller (we ignore other attrs — none matter). */
        int ds = 0;
        pthread_attr_getdetachstate((pthread_attr_t *)a, &ds);
        pthread_attr_setdetachstate(&my, ds);
        if (sz < (4u << 20)) sz = 4u << 20;
        pthread_attr_setstacksize(&my, sz);
    } else {
        pthread_attr_setstacksize(&my, 4u << 20);
    }
    int rc = real_pthread_create(t, &my, fn, arg);
    pthread_attr_destroy(&my);
    return rc;
}
