#!/usr/bin/env python3
"""setup_apk.py — Download Wyze APK and extract SDK libraries.

This script automates the first-time setup:
  1. Downloads the Wyze app XAPK from APKPure
  2. Extracts the arm64 native libraries (libiotp2pav.so, libmbedtls.so)
  3. Places them in the correct directory for the bridge builder

Usage:
  python3 scripts/setup_apk.py

  Or via Docker:
  docker compose run --rm bridge-builder python3 /work/scripts/setup_apk.py

Output:
  apk/xapk_contents/arm64_libs/lib/arm64-v8a/libiotp2pav.so
  apk/xapk_contents/arm64_libs/lib/arm64-v8a/libmbedtls.so
"""

import os
import sys
import zipfile
import tempfile
import urllib.request
import shutil
from pathlib import Path

# --- Configuration ---

WYZE_PACKAGE = "com.hualai"
APKPURE_URL = f"https://d.apkpure.net/b/XAPK/{WYZE_PACKAGE}?version=latest"
# Fallback: direct APKPure page (user may need to download manually)
APKPURE_PAGE = f"https://apkpure.com/wyze/com.hualai/download"

# Libraries we need from the APK
REQUIRED_LIBS = ["libiotp2pav.so", "libmbedtls.so"]

# Output directory (relative to project root)
OUTPUT_DIR = Path("apk/xapk_contents/arm64_libs/lib/arm64-v8a")

# Where to store the downloaded XAPK
XAPK_PATH = Path("apk/wyze.xapk")


def log(msg: str):
    print(f"[setup-apk] {msg}", flush=True)


def check_existing():
    """Check if libs are already extracted."""
    missing = []
    for lib in REQUIRED_LIBS:
        path = OUTPUT_DIR / lib
        if not path.is_file():
            missing.append(lib)
    return missing


def download_xapk():
    """Download the Wyze XAPK from APKPure."""
    if XAPK_PATH.is_file():
        log(f"XAPK already exists: {XAPK_PATH} ({XAPK_PATH.stat().st_size // 1024 // 1024}MB)")
        return True

    XAPK_PATH.parent.mkdir(parents=True, exist_ok=True)

    log("Downloading Wyze XAPK from APKPure...")
    log(f"  URL: {APKPURE_URL}")

    try:
        req = urllib.request.Request(APKPURE_URL, headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36",
            "Accept": "application/vnd.android.package-archive, application/octet-stream, */*",
        })
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            with open(str(XAPK_PATH) + ".tmp", "wb") as f:
                while True:
                    chunk = resp.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = downloaded * 100 // total
                        print(f"\r[setup-apk]   {downloaded // 1024 // 1024}MB / {total // 1024 // 1024}MB ({pct}%)", end="", flush=True)
                    else:
                        print(f"\r[setup-apk]   {downloaded // 1024 // 1024}MB downloaded", end="", flush=True)
            print()

        os.rename(str(XAPK_PATH) + ".tmp", str(XAPK_PATH))
        log(f"  Downloaded: {XAPK_PATH} ({XAPK_PATH.stat().st_size // 1024 // 1024}MB)")
        return True

    except Exception as e:
        log(f"  Download failed: {e}")
        log(f"")
        log(f"  Please download the Wyze XAPK manually:")
        log(f"    1. Go to: {APKPURE_PAGE}")
        log(f"    2. Download the XAPK file")
        log(f"    3. Save it as: {XAPK_PATH}")
        log(f"    4. Re-run this script")
        # Clean up partial download
        tmp = Path(str(XAPK_PATH) + ".tmp")
        if tmp.exists():
            tmp.unlink()
        return False


def extract_libs():
    """Extract required native libraries from the XAPK."""
    if not XAPK_PATH.is_file():
        log(f"ERROR: XAPK not found at {XAPK_PATH}")
        return False

    log(f"Extracting libraries from {XAPK_PATH}...")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Step 1: Extract the XAPK (it's a zip of APKs)
        log("  Step 1: Unpacking XAPK...")
        with zipfile.ZipFile(XAPK_PATH) as xapk:
            # Look for the arm64 config APK
            arm64_apk = None
            for name in xapk.namelist():
                if "arm64" in name.lower() and name.endswith(".apk"):
                    arm64_apk = name
                    break

            if not arm64_apk:
                # Try extracting all and looking for the libs directly
                log("  No arm64 APK found in XAPK. Searching all entries...")
                for name in xapk.namelist():
                    basename = os.path.basename(name)
                    if basename in REQUIRED_LIBS:
                        log(f"  Found {basename} at {name}")
                        xapk.extract(name, tmpdir)
                        dest = OUTPUT_DIR / basename
                        shutil.copy2(tmpdir / name, dest)
                        log(f"  Extracted: {dest}")

                # Check if we got everything
                missing = check_existing()
                if not missing:
                    return True
                log(f"  Still missing: {missing}")
                return False

            log(f"  Found arm64 APK: {arm64_apk}")
            xapk.extract(arm64_apk, tmpdir)
            arm64_path = tmpdir / arm64_apk

        # Step 2: Extract native libs from the arm64 APK
        log("  Step 2: Extracting native libs from arm64 APK...")
        with zipfile.ZipFile(arm64_path) as apk:
            extracted = 0
            for name in apk.namelist():
                basename = os.path.basename(name)
                if basename in REQUIRED_LIBS:
                    apk.extract(name, tmpdir)
                    dest = OUTPUT_DIR / basename
                    shutil.copy2(tmpdir / name, dest)
                    size = dest.stat().st_size
                    log(f"  Extracted: {basename} ({size:,} bytes)")
                    extracted += 1

            if extracted == 0:
                log("  WARNING: No required libs found in arm64 APK")
                log(f"  APK contents: {apk.namelist()[:10]}...")
                return False

    return True


def verify():
    """Verify all required libraries are present."""
    missing = check_existing()
    if missing:
        log(f"ERROR: Missing libraries: {missing}")
        return False

    log("Verification:")
    for lib in REQUIRED_LIBS:
        path = OUTPUT_DIR / lib
        size = path.stat().st_size
        log(f"  {lib}: {size:,} bytes")

    log("")
    log("Setup complete! Libraries are ready for the bridge builder.")
    return True


def main():
    log("Wyze APK SDK Library Setup")
    log("")

    # Check if already done
    missing = check_existing()
    if not missing:
        log("All required libraries already present:")
        for lib in REQUIRED_LIBS:
            path = OUTPUT_DIR / lib
            log(f"  {path}: {path.stat().st_size:,} bytes")
        log("Nothing to do.")
        return 0

    log(f"Missing libraries: {missing}")
    log("")

    # Download XAPK
    if not download_xapk():
        return 1

    # Extract libs
    if not extract_libs():
        return 1

    # Verify
    if not verify():
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
