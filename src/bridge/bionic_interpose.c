/*
 * bionic_interpose.c
 *
 * Shared library that interposes libc functions needed by the Android SDK.
 * Must be loaded via LD_PRELOAD before the SDK .so to avoid re-entrancy
 * in musl's dynamic linker.
 *
 * Provides:
 *   - __sF array + fprintf/vfprintf/fputc/fclose translation
 *   - pthread_create with enlarged stack size
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>

/* ---------------------------------------------------------------- __sF stdio
 *
 * Bionic: stdin = &__sF[0], stdout = &__sF[1], stderr = &__sF[2]
 * Bionic FILE is 152 bytes. SDK computes &__sF[2] as __sF + 304 (= 0x130).
 */
#define SF_SLOT_SIZE 512
typedef struct { char _pad[SF_SLOT_SIZE]; } _bionic_file_slot;
_bionic_file_slot __sF[3];

static int _sf_slot(FILE *f) {
    char *p = (char *)f;
    char *base = (char *)&__sF[0];
    if (p < base || p >= base + sizeof(__sF)) return -1;
    size_t off = (size_t)(p - base);
    if (off < SF_SLOT_SIZE) return 0;
    if (off < 2 * SF_SLOT_SIZE) return 1;
    return 2;
}

static FILE *_translate(FILE *f) {
    switch (_sf_slot(f)) {
        case 0:  return stdin;
        case 1:  return stdout;
        case 2:  return stderr;
        default: return f;
    }
}

/* Use RTLD_NEXT to call the real musl implementations */
static int (*_real_vfprintf)(FILE *, const char *, va_list);
static int (*_real_fputc)(int, FILE *);
static int (*_real_fclose)(FILE *);
static int (*_real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                    void *(*)(void *), void *);

__attribute__((constructor))
static void _interpose_init(void) {
    _real_vfprintf      = dlsym(RTLD_NEXT, "vfprintf");
    _real_fputc         = dlsym(RTLD_NEXT, "fputc");
    _real_fclose        = dlsym(RTLD_NEXT, "fclose");
    _real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
}

int fprintf(FILE *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = _real_vfprintf ? _real_vfprintf(_translate(f), fmt, ap) : 0;
    va_end(ap);
    return r;
}

int vfprintf(FILE *f, const char *fmt, va_list ap) {
    return _real_vfprintf ? _real_vfprintf(_translate(f), fmt, ap) : 0;
}

int fputc(int c, FILE *f) {
    return _real_fputc ? _real_fputc(c, _translate(f)) : c;
}

int fclose(FILE *f) {
    if (_sf_slot(f) >= 0) return 0;  /* don't close stdin/stdout/stderr */
    return _real_fclose ? _real_fclose(f) : 0;
}

/* Enlarge SDK thread stacks (bionic default 1MB, musl default 80KB) */
int pthread_create(pthread_t *t, const pthread_attr_t *a,
                   void *(*fn)(void *), void *arg) {
    if (!_real_pthread_create)
        _real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    if (!_real_pthread_create) return -1;

    pthread_attr_t my;
    pthread_attr_init(&my);
    if (a) {
        size_t sz = 0;
        pthread_attr_getstacksize((pthread_attr_t *)a, &sz);
        int ds = 0;
        pthread_attr_getdetachstate((pthread_attr_t *)a, &ds);
        pthread_attr_setdetachstate(&my, ds);
        if (sz < (4u << 20)) sz = 4u << 20;
        pthread_attr_setstacksize(&my, sz);
    } else {
        pthread_attr_setstacksize(&my, 4u << 20);
    }
    int rc = _real_pthread_create(t, &my, fn, arg);
    pthread_attr_destroy(&my);
    return rc;
}
