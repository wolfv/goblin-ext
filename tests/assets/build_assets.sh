#!/bin/bash
# Build test assets for goblin-ext codesign tests
# Run this script on macOS to regenerate the test binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Detect current architecture
CURRENT_ARCH=$(uname -m)
echo "Current architecture: $CURRENT_ARCH"

# Create temp source files
cat > /tmp/test_main.c << 'EOF'
int main(void) {
    return 0;
}
EOF

cat > /tmp/test_dylib.c << 'EOF'
__attribute__((visibility("default")))
int add(int a, int b) {
    return a + b;
}
EOF

echo "Building test binaries..."

# Build for current architecture (unsigned)
echo "  Building unsigned executable..."
clang -o test_exe_unsigned /tmp/test_main.c
# Strip signature if present
codesign --remove-signature test_exe_unsigned 2>/dev/null || true

echo "  Building unsigned dylib..."
clang -dynamiclib -install_name @rpath/libtest.dylib -o libtest_unsigned.dylib /tmp/test_dylib.c
codesign --remove-signature libtest_unsigned.dylib 2>/dev/null || true

# Build linker-signed versions (default on modern macOS)
echo "  Building linker-signed executable..."
clang -o test_exe_linker_signed /tmp/test_main.c

echo "  Building linker-signed dylib..."
clang -dynamiclib -install_name @rpath/libtest.dylib -o libtest_linker_signed.dylib /tmp/test_dylib.c

# Build ad-hoc signed versions
echo "  Building adhoc-signed executable..."
clang -o test_exe_adhoc /tmp/test_main.c
codesign -s - -f -i com.test.exe test_exe_adhoc

echo "  Building adhoc-signed dylib..."
clang -dynamiclib -install_name @rpath/libtest.dylib -o libtest_adhoc.dylib /tmp/test_dylib.c
codesign -s - -f -i com.test.dylib libtest_adhoc.dylib

# Build with hardened runtime
echo "  Building hardened runtime executable..."
clang -o test_exe_hardened /tmp/test_main.c
codesign -s - -f -i com.test.exe --options runtime test_exe_hardened

# Try to build universal binaries if both architectures are available
if [ "$CURRENT_ARCH" = "arm64" ]; then
    OTHER_ARCH="x86_64"
else
    OTHER_ARCH="arm64"
fi

# Check if we can cross-compile
if clang -arch $OTHER_ARCH -o /dev/null /tmp/test_main.c 2>/dev/null; then
    echo "  Building universal (fat) binary..."
    clang -arch arm64 -o /tmp/test_arm64 /tmp/test_main.c
    clang -arch x86_64 -o /tmp/test_x86_64 /tmp/test_main.c
    lipo -create /tmp/test_arm64 /tmp/test_x86_64 -output test_exe_fat
    codesign -s - -f -i com.test.fat test_exe_fat
    rm /tmp/test_arm64 /tmp/test_x86_64
else
    echo "  Skipping universal binary (cross-compilation not available)"
fi

# Clean up
rm /tmp/test_main.c /tmp/test_dylib.c

echo ""
echo "Built test assets:"
ls -la *.dylib test_exe_* 2>/dev/null || true

echo ""
echo "Signature info:"
for f in test_exe_* *.dylib; do
    echo "  $f:"
    codesign -dvv "$f" 2>&1 | grep -E "(Identifier|CDHash|flags)" | head -3 || echo "    (unsigned)"
done
