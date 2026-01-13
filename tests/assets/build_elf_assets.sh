#!/bin/bash
# Build ELF test assets for goblin-ext testing
# Run this script to generate test binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building ELF test assets in $SCRIPT_DIR"
echo "============================================"

# Simple C program that uses dynamic linking
cat > /tmp/test_elf.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("Hello from test ELF binary!\n");
    return 0;
}
EOF

# Simple shared library
cat > /tmp/test_lib.c << 'EOF'
#include <stdio.h>

void hello_lib(void) {
    printf("Hello from shared library!\n");
}

int add_numbers(int a, int b) {
    return a + b;
}
EOF

# Program that uses the library
cat > /tmp/test_with_lib.c << 'EOF'
#include <stdio.h>

extern void hello_lib(void);
extern int add_numbers(int a, int b);

int main(int argc, char *argv[]) {
    hello_lib();
    printf("2 + 3 = %d\n", add_numbers(2, 3));
    return 0;
}
EOF

# 1. Basic x86_64 ELF executable
echo "Building: test_elf_x86_64 (basic executable)"
gcc -o "$SCRIPT_DIR/test_elf_x86_64" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build x86_64 binary"

# 2. ELF with RUNPATH (DT_RUNPATH)
echo "Building: test_elf_with_rpath (has RUNPATH)"
gcc -o "$SCRIPT_DIR/test_elf_with_rpath" -Wl,-rpath,/usr/local/lib:/opt/lib /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build binary with rpath"

# 3. ELF with old-style DT_RPATH (using --disable-new-dtags)
echo "Building: test_elf_with_old_rpath (has DT_RPATH)"
gcc -o "$SCRIPT_DIR/test_elf_with_old_rpath" -Wl,--disable-new-dtags,-rpath,/usr/lib/custom /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build binary with old-style rpath"

# 4. PIE executable (Position Independent Executable)
echo "Building: test_elf_pie (PIE executable)"
gcc -pie -o "$SCRIPT_DIR/test_elf_pie" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build PIE binary"

# 5. Non-PIE executable (traditional executable)
echo "Building: test_elf_no_pie (non-PIE executable)"
gcc -no-pie -o "$SCRIPT_DIR/test_elf_no_pie" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build non-PIE binary"

# 6. Shared library (.so)
echo "Building: libtest.so (shared library)"
gcc -shared -fPIC -o "$SCRIPT_DIR/libtest.so" /tmp/test_lib.c 2>/dev/null || \
    echo "  Warning: Could not build shared library"

# 7. Shared library with SONAME
echo "Building: libtest_soname.so (shared library with SONAME)"
gcc -shared -fPIC -Wl,-soname,libtest.so.1 -o "$SCRIPT_DIR/libtest_soname.so" /tmp/test_lib.c 2>/dev/null || \
    echo "  Warning: Could not build shared library with SONAME"

# 8. Shared library with RPATH
echo "Building: libtest_with_rpath.so (shared library with RPATH)"
gcc -shared -fPIC -Wl,-rpath,/opt/deps/lib -o "$SCRIPT_DIR/libtest_with_rpath.so" /tmp/test_lib.c 2>/dev/null || \
    echo "  Warning: Could not build shared library with rpath"

# 9. ELF with very long RPATH (to test shrinking)
LONG_RPATH="/very/long/path/that/exceeds/typical/length/for/testing/purposes/one"
LONG_RPATH="$LONG_RPATH:/very/long/path/that/exceeds/typical/length/for/testing/purposes/two"
LONG_RPATH="$LONG_RPATH:/very/long/path/that/exceeds/typical/length/for/testing/purposes/three"
LONG_RPATH="$LONG_RPATH:/very/long/path/that/exceeds/typical/length/for/testing/purposes/four"
echo "Building: test_elf_long_rpath (very long RPATH, ${#LONG_RPATH} chars)"
gcc -o "$SCRIPT_DIR/test_elf_long_rpath" -Wl,-rpath,"$LONG_RPATH" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build binary with long rpath"

# 10. Stripped binary (no debug symbols)
echo "Building: test_elf_stripped (stripped of symbols)"
gcc -o "$SCRIPT_DIR/test_elf_stripped" /tmp/test_elf.c 2>/dev/null && \
    strip "$SCRIPT_DIR/test_elf_stripped" 2>/dev/null || \
    echo "  Warning: Could not build stripped binary"

# 11. Binary with debug info
echo "Building: test_elf_debug (with debug info)"
gcc -g -o "$SCRIPT_DIR/test_elf_debug" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build debug binary"

# 12. Executable that links to a library (has DT_NEEDED entries)
echo "Building: test_elf_with_needed (links to libm)"
cat > /tmp/test_with_math.c << 'EOF'
#include <stdio.h>
#include <math.h>

int main(int argc, char *argv[]) {
    printf("sqrt(2) = %f\n", sqrt(2.0));
    return 0;
}
EOF
gcc -o "$SCRIPT_DIR/test_elf_with_needed" /tmp/test_with_math.c -lm 2>/dev/null || \
    echo "  Warning: Could not build binary with library dependency"

# 13. 32-bit binary (if cross-compilation is available)
echo "Building: test_elf_i386 (32-bit binary, requires multilib)"
gcc -m32 -o "$SCRIPT_DIR/test_elf_i386" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build 32-bit binary (install gcc-multilib)"

# 14. Static-PIE (if supported)
echo "Building: test_elf_static_pie (static PIE)"
gcc -static-pie -o "$SCRIPT_DIR/test_elf_static_pie" /tmp/test_elf.c 2>/dev/null || \
    echo "  Warning: Could not build static-pie binary"

# Cleanup
rm -f /tmp/test_elf.c /tmp/test_lib.c /tmp/test_with_lib.c /tmp/test_with_math.c

echo ""
echo "============================================"
echo "Build complete! Test assets:"
echo ""

# List all built assets with their properties
for f in "$SCRIPT_DIR"/test_elf_* "$SCRIPT_DIR"/libtest*.so; do
    if [ -f "$f" ]; then
        SIZE=$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f" 2>/dev/null)
        TYPE=$(file -b "$f" | head -c 60)
        RPATH=$(readelf -d "$f" 2>/dev/null | grep -E 'RPATH|RUNPATH' | head -1 | sed 's/.*\[/[/' || echo "")
        printf "  %-30s %6s bytes  %s\n" "$(basename "$f")" "$SIZE" "$RPATH"
    fi
done

echo ""
echo "Use 'readelf -d <file>' to inspect dynamic sections"
echo "Use 'readelf -l <file>' to inspect program headers"
