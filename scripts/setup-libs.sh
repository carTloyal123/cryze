#!/bin/sh
# setup-libs.sh — Create musl-compatible shim libraries and patch Android .so files
#
# android_stubs.c provides bionic symbols (__errno, arc4random, etc.) from the executable.
# bionic_interpose.c provides __sF/fprintf/pthread_create as LD_PRELOAD'd .so.
#
# The Android .so files from the APK need patching with patchelf to:
#   1. Remove DT_NEEDED entries for bionic libs (libc.so, libm.so, libdl.so, liblog.so)
#      since those symbols are provided by our stubs or musl equivalents
#   2. Rename libstdc++.so -> libstdc++.so.6 to match the system library
set -eu

OUT="/work/libs"
APK_LIBS="/apk/xapk_contents/arm64_libs/lib/arm64-v8a"

# ===========================================================================
# Step 0: Clean slate — remove any previous libs so we start fresh
# ===========================================================================

echo "[setup] Cleaning $OUT..."
rm -rf "$OUT"
mkdir -p "$OUT"

# ===========================================================================
# Step 1: Compile shim libraries
# ===========================================================================

echo "[setup] Compiling bionic_interpose.so..."
gcc -shared -o "$OUT/bionic_interpose.so" /work/src/bionic_interpose.c -fPIC -ldl -lpthread

echo "[setup] Creating shim libraries..."

# liblog.so — stub with weak symbols. bridge exe provides the strong ones via -rdynamic.
cat > /tmp/shim_log.c << 'EOF'
#include <stdio.h>
#include <stdarg.h>
__attribute__((weak)) int __android_log_print(int p, const char* t, const char* f, ...) {
    (void)p; (void)t; (void)f; return 0;
}
__attribute__((weak)) int __android_log_write(int p, const char* t, const char* m) {
    (void)p; (void)t; (void)m; return 0;
}
__attribute__((weak)) int __android_log_vprint(int p, const char* t, const char* f, va_list a) {
    (void)p; (void)t; (void)f; (void)a; return 0;
}
EOF
gcc -shared -o "$OUT/liblog.so" /tmp/shim_log.c -fPIC

# libc.so — symlink to musl
ln -sf /lib/ld-musl-aarch64.so.1 "$OUT/libc.so"

# libm.so, libdl.so — empty stubs (musl has these in libc)
echo 'void __stub(void){}' | gcc -shared -o "$OUT/libm.so" -x c - -fPIC
echo 'void __stub(void){}' | gcc -shared -o "$OUT/libdl.so" -x c - -fPIC

# libstdc++.so — point to system
ln -sf /usr/lib/libstdc++.so.6 "$OUT/libstdc++.so"

# ===========================================================================
# Step 2: Build ELF patcher for NULL INIT/FINI_ARRAY entries
# ===========================================================================
# Android's bionic linker skips NULL entries in INIT_ARRAY/FINI_ARRAY, but
# musl calls them unconditionally → SIGSEGV at pc=0. The Android .so files
# have NULL placeholder entries in these arrays (no relocation to fill them).
# We zero out INIT_ARRAYSZ and FINI_ARRAYSZ so musl's linker skips them.

echo ""
echo "[setup] Building ELF init_array patcher..."
cat > /tmp/patch_init.c << 'PATCH_EOF'
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Zero out DT_INIT_ARRAYSZ and DT_FINI_ARRAYSZ in an ELF64 dynamic section.
 * This prevents musl from calling NULL constructor/destructor entries that
 * Android's bionic linker would silently skip. */
int main(int argc, char** argv) {
    for (int a = 1; a < argc; ++a) {
        FILE* f = fopen(argv[a], "r+b");
        if (!f) { perror(argv[a]); return 1; }

        /* Read ELF header */
        uint8_t ehdr[64];
        if (fread(ehdr, 1, 64, f) != 64 || memcmp(ehdr, "\x7f" "ELF", 4) != 0) {
            fprintf(stderr, "%s: not ELF\n", argv[a]); fclose(f); return 1;
        }
        if (ehdr[4] != 2) {  /* EI_CLASS = ELFCLASS64 */
            fprintf(stderr, "%s: not 64-bit\n", argv[a]); fclose(f); return 1;
        }

        uint16_t e_phoff_off = 32;
        uint16_t e_phentsize_off = 54;
        uint16_t e_phnum_off = 56;

        uint64_t e_phoff;
        uint16_t e_phentsize, e_phnum;
        memcpy(&e_phoff, ehdr + e_phoff_off, 8);
        memcpy(&e_phentsize, ehdr + e_phentsize_off, 2);
        memcpy(&e_phnum, ehdr + e_phnum_off, 2);

        /* Find PT_DYNAMIC */
        uint64_t dyn_offset = 0, dyn_size = 0;
        for (int i = 0; i < e_phnum; ++i) {
            uint8_t phdr[64];
            fseek(f, e_phoff + i * e_phentsize, SEEK_SET);
            fread(phdr, 1, e_phentsize, f);
            uint32_t p_type;
            memcpy(&p_type, phdr, 4);
            if (p_type == 2) { /* PT_DYNAMIC */
                memcpy(&dyn_offset, phdr + 8, 8);
                memcpy(&dyn_size, phdr + 32, 8);
                break;
            }
        }
        if (!dyn_offset) {
            fprintf(stderr, "%s: no PT_DYNAMIC\n", argv[a]); fclose(f); return 1;
        }

        /* Scan dynamic entries, zero INIT_ARRAYSZ(0x1b) and FINI_ARRAYSZ(0x1c) */
        int patched = 0;
        for (uint64_t pos = dyn_offset; pos < dyn_offset + dyn_size; pos += 16) {
            uint8_t entry[16];
            fseek(f, pos, SEEK_SET);
            if (fread(entry, 1, 16, f) != 16) break;
            int64_t tag;
            memcpy(&tag, entry, 8);
            if (tag == 0) break; /* DT_NULL */
            if (tag == 0x1b || tag == 0x1c) { /* DT_INIT_ARRAYSZ or DT_FINI_ARRAYSZ */
                uint64_t zero = 0;
                fseek(f, pos + 8, SEEK_SET);
                fwrite(&zero, 1, 8, f);
                fprintf(stderr, "  %s: zeroed %s\n", argv[a],
                        tag == 0x1b ? "INIT_ARRAYSZ" : "FINI_ARRAYSZ");
                ++patched;
            }
        }
        fclose(f);
        if (!patched) fprintf(stderr, "  %s: no INIT/FINI_ARRAYSZ found\n", argv[a]);
    }
    return 0;
}
PATCH_EOF
gcc -o /tmp/patch_init /tmp/patch_init.c

# ===========================================================================
# Step 3: Patch Android .so files
# ===========================================================================
# Two kinds of patching:
#   a) patchelf: strip bionic DT_NEEDED, remap libstdc++.so → libstdc++.so.6
#   b) patch_init: zero INIT/FINI_ARRAYSZ to avoid NULL constructor calls

echo "[setup] Patching APK shared libraries..."

# --- libiotp2pav.so (primary SDK library) ---
echo "  patching libiotp2pav.so..."
cp "$APK_LIBS/libiotp2pav.so" "$OUT/libiotp2pav.so"
patchelf --remove-needed libc.so    "$OUT/libiotp2pav.so"
patchelf --remove-needed libm.so    "$OUT/libiotp2pav.so"
patchelf --remove-needed libdl.so   "$OUT/libiotp2pav.so"
patchelf --remove-needed liblog.so  "$OUT/libiotp2pav.so"
patchelf --replace-needed libstdc++.so libstdc++.so.6 "$OUT/libiotp2pav.so"
/tmp/patch_init "$OUT/libiotp2pav.so"

# --- libmbedtls.so (TLS library used by libiotp2pav) ---
echo "  patching libmbedtls.so..."
cp "$APK_LIBS/libmbedtls.so" "$OUT/libmbedtls.so"
patchelf --remove-needed libc.so    "$OUT/libmbedtls.so"
patchelf --remove-needed libm.so    "$OUT/libmbedtls.so"
patchelf --remove-needed libdl.so   "$OUT/libmbedtls.so"
patchelf --replace-needed libstdc++.so libstdc++.so.6 "$OUT/libmbedtls.so"
/tmp/patch_init "$OUT/libmbedtls.so"

# ===========================================================================
# Step 4: Verify
# ===========================================================================

echo ""
echo "[setup] Verifying patched libraries..."
echo "  libiotp2pav.so NEEDED:"
patchelf --print-needed "$OUT/libiotp2pav.so" 2>&1 | sed 's/^/    /'
echo "  libmbedtls.so NEEDED:"
patchelf --print-needed "$OUT/libmbedtls.so" 2>&1 | sed 's/^/    /'

echo ""
echo "[setup] Checking ldd resolution..."
LD_LIBRARY_PATH="$OUT:$APK_LIBS" ldd "$OUT/libiotp2pav.so" 2>&1 | sed 's/^/  /' || true

echo ""
echo "[setup] Done."
ls -lh "$OUT/"
