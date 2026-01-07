#!/usr/bin/env python3
"""
Test framework for comparing goblin-ext's ad-hoc code signing against Apple's codesign.

This script tests ad-hoc code signing and compares the output of goblin-ext's
implementation against Apple's official codesign tool.

Usage:
    python test_codesign.py [options]

Options:
    --goblin-tool PATH    Path to goblin-ext's install_name_tool binary
    --verbose, -v         Verbose output
    --keep-temp           Keep temporary files for inspection
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional


class TestResult(Enum):
    PASS = auto()
    FAIL = auto()
    SKIP = auto()
    ERROR = auto()


@dataclass
class TestCase:
    name: str
    result: TestResult = TestResult.SKIP
    error_message: str = ""
    goblin_size: int = 0
    apple_size: int = 0
    diff_offset: Optional[int] = None


# Minimal C program for testing
MINIMAL_MAIN = '''
int main(void) {
    return 0;
}
'''

# Minimal dylib for testing
MINIMAL_DYLIB = '''
__attribute__((visibility("default")))
int add(int a, int b) {
    return a + b;
}
'''


def create_test_binary(tmpdir: Path, name: str, is_dylib: bool = False) -> Optional[Path]:
    """Create a minimal test binary using clang."""
    source_file = tmpdir / f"{name}.c"
    output_file = tmpdir / (f"lib{name}.dylib" if is_dylib else name)

    source_code = MINIMAL_DYLIB if is_dylib else MINIMAL_MAIN
    source_file.write_text(source_code)

    cmd = ["clang", "-o", str(output_file), str(source_file)]
    if is_dylib:
        cmd.extend(["-dynamiclib", "-install_name", f"@rpath/lib{name}.dylib"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"Failed to compile {name}: {result.stderr}")
            return None
        return output_file
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Failed to compile {name}: {e}")
        return None


def get_prebuilt_assets() -> Optional[Path]:
    """Get the path to pre-built test assets if available."""
    script_dir = Path(__file__).parent
    assets_dir = script_dir.parent / "assets"
    if assets_dir.exists() and (assets_dir / "test_exe_linker_signed").exists():
        return assets_dir
    return None


def copy_asset_to_temp(assets_dir: Path, asset_name: str, tmpdir: Path) -> Optional[Path]:
    """Copy a pre-built asset to the temp directory."""
    src = assets_dir / asset_name
    if not src.exists():
        return None
    dst = tmpdir / asset_name
    shutil.copy(src, dst)
    os.chmod(dst, 0o755)
    return dst


def get_codesign_info(path: Path) -> dict:
    """Get code signature information using codesign -d."""
    info = {
        "signed": False,
        "identifier": None,
        "flags": None,
        "adhoc": False,
        "linker_signed": False,
    }

    try:
        result = subprocess.run(
            ["codesign", "-d", "-vvv", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stderr  # codesign outputs to stderr

        if "code object is not signed at all" in output.lower():
            return info

        info["signed"] = True

        for line in output.split("\n"):
            if line.startswith("Identifier="):
                info["identifier"] = line.split("=", 1)[1]
            elif line.startswith("CodeDirectory"):
                if "flags=0x" in line:
                    # Parse flags
                    flags_part = line.split("flags=")[1].split()[0]
                    if "adhoc" in line.lower():
                        info["adhoc"] = True
                    if "linker-signed" in line.lower() or "linkerSigned" in line:
                        info["linker_signed"] = True

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return info


def compare_binaries_bitwise(path1: Path, path2: Path) -> tuple[bool, str, Optional[int]]:
    """Compare two binary files byte-by-byte."""
    data1 = path1.read_bytes()
    data2 = path2.read_bytes()

    if data1 == data2:
        return True, "Identical", None

    # Find first difference
    min_len = min(len(data1), len(data2))
    for i in range(min_len):
        if data1[i] != data2[i]:
            context_start = max(0, i - 8)
            context_end = min(min_len, i + 8)
            hex1 = data1[context_start:context_end].hex()
            hex2 = data2[context_start:context_end].hex()
            return False, f"Diff at 0x{i:x}: {hex1} vs {hex2}", i

    if len(data1) != len(data2):
        return False, f"Size diff: {len(data1)} vs {len(data2)} bytes", min_len

    return False, "Unknown difference", None


def compare_code_signature(path1: Path, path2: Path) -> tuple[bool, str]:
    """Compare the code signatures of two binaries structurally."""
    info1 = get_codesign_info(path1)
    info2 = get_codesign_info(path2)

    if info1["signed"] != info2["signed"]:
        return False, f"Signed status differs: {info1['signed']} vs {info2['signed']}"

    if not info1["signed"]:
        return True, "Both unsigned"

    differences = []

    if info1["identifier"] != info2["identifier"]:
        differences.append(f"identifier: {info1['identifier']} vs {info2['identifier']}")

    if info1["adhoc"] != info2["adhoc"]:
        differences.append(f"adhoc: {info1['adhoc']} vs {info2['adhoc']}")

    if differences:
        return False, "; ".join(differences)

    return True, "Signatures match structurally"


def verify_signature(path: Path) -> tuple[bool, str]:
    """Verify a code signature using codesign -v.

    Returns (True, "") if valid, (False, error_message) if invalid.
    """
    try:
        result = subprocess.run(
            ["codesign", "-v", "--strict", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True, ""
        # codesign outputs errors to stderr
        error = result.stderr.strip() or result.stdout.strip() or "Unknown verification error"
        return False, error
    except subprocess.TimeoutExpired:
        return False, "Verification timeout"
    except FileNotFoundError:
        return False, "codesign not found"


def sign_with_apple_codesign(input_path: Path, output_path: Path, identifier: str,
                             hardened_runtime: bool = False,
                             preserve_entitlements: bool = False) -> tuple[bool, str]:
    """Sign a binary with Apple's codesign tool."""
    shutil.copy(input_path, output_path)
    os.chmod(output_path, 0o755)

    cmd = ["codesign", "-s", "-", "-f", "-i", identifier]

    if hardened_runtime:
        cmd.extend(["--options", "runtime"])

    cmd.append(str(output_path))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "codesign not found"


def sign_with_goblin(goblin_tool: Path, input_path: Path, output_path: Path,
                     identifier: str, hardened_runtime: bool = False,
                     preserve_entitlements: bool = False) -> tuple[bool, str]:
    """Sign a binary using goblin-ext's install_name_tool --sign."""
    shutil.copy(input_path, output_path)
    os.chmod(output_path, 0o755)

    cmd = [str(goblin_tool), "--sign", "-i", identifier]

    if hardened_runtime:
        cmd.append("--options=runtime")

    cmd.append(str(output_path))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip() or "Unknown error"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, f"Goblin tool not found at {goblin_tool}"


def test_adhoc_signing(goblin_tool: Path, binary_path: Path, tmpdir: Path,
                       identifier: str, hardened_runtime: bool = False,
                       verbose: bool = False, strict: bool = False) -> TestCase:
    """Test ad-hoc signing comparing Apple and goblin implementations.

    Args:
        strict: If True, require bit-for-bit identical output.
                If False (default), pass if signatures are structurally equivalent.
    """
    name = f"adhoc{'_hardened' if hardened_runtime else ''}"
    tc = TestCase(name=name)

    # Use the same filename for both to ensure identical identifiers
    # (codesign uses filename as default identifier component)
    test_file = tmpdir / "testbinary"
    apple_result = tmpdir / "apple_result"

    # Sign with Apple's codesign
    apple_ok, apple_err = sign_with_apple_codesign(
        binary_path, test_file, identifier, hardened_runtime
    )
    if not apple_ok:
        tc.result = TestResult.SKIP
        tc.error_message = f"Apple codesign failed: {apple_err}"
        return tc

    # Save Apple's result
    shutil.copy(test_file, apple_result)
    tc.apple_size = apple_result.stat().st_size

    # Sign with goblin tool (overwrites test_file)
    goblin_ok, goblin_err = sign_with_goblin(
        goblin_tool, binary_path, test_file, identifier, hardened_runtime
    )
    if not goblin_ok:
        tc.result = TestResult.ERROR
        tc.error_message = f"Goblin signing failed: {goblin_err}"
        return tc

    tc.goblin_size = test_file.stat().st_size

    # First verify that macOS accepts our signature
    verify_ok, verify_err = verify_signature(test_file)
    if not verify_ok:
        tc.result = TestResult.FAIL
        tc.error_message = f"Goblin signature rejected by codesign -v: {verify_err}"
        return tc

    # Compare byte-by-byte first
    match, msg, diff_offset = compare_binaries_bitwise(test_file, apple_result)
    tc.diff_offset = diff_offset

    if match:
        tc.result = TestResult.PASS
        if verbose:
            print(f"    Bit-for-bit identical!")
    else:
        # Check if signatures are at least structurally equivalent
        struct_match, struct_msg = compare_code_signature(test_file, apple_result)
        if struct_match:
            if strict:
                tc.result = TestResult.FAIL
                tc.error_message = f"Structural match but byte diff: {msg}"
            else:
                # Non-strict mode: structural match is good enough
                tc.result = TestResult.PASS
                if verbose:
                    print(f"    Structural match (not bit-for-bit)")
        else:
            tc.result = TestResult.FAIL
            tc.error_message = f"Signature mismatch: {struct_msg}; {msg}"

    return tc


def test_resign_linker_signed(goblin_tool: Path, binary_path: Path, tmpdir: Path,
                               identifier: str, verbose: bool = False) -> TestCase:
    """Test re-signing a linker-signed binary."""
    tc = TestCase(name="resign_linker_signed")

    test_file = tmpdir / "testbinary"
    apple_result = tmpdir / "apple_result"

    # First check if the binary is linker-signed
    info = get_codesign_info(binary_path)
    if not info.get("linker_signed"):
        tc.result = TestResult.SKIP
        tc.error_message = "Binary is not linker-signed"
        return tc

    # Sign with Apple's codesign
    apple_ok, apple_err = sign_with_apple_codesign(binary_path, test_file, identifier)
    if not apple_ok:
        tc.result = TestResult.SKIP
        tc.error_message = f"Apple codesign failed: {apple_err}"
        return tc

    shutil.copy(test_file, apple_result)
    tc.apple_size = apple_result.stat().st_size

    # Sign with goblin tool
    goblin_ok, goblin_err = sign_with_goblin(goblin_tool, binary_path, test_file, identifier)
    if not goblin_ok:
        tc.result = TestResult.ERROR
        tc.error_message = f"Goblin signing failed: {goblin_err}"
        return tc

    tc.goblin_size = test_file.stat().st_size

    # First verify that macOS accepts our signature
    verify_ok, verify_err = verify_signature(test_file)
    if not verify_ok:
        tc.result = TestResult.FAIL
        tc.error_message = f"Goblin signature rejected by codesign -v: {verify_err}"
        return tc

    # Compare
    match, msg, diff_offset = compare_binaries_bitwise(test_file, apple_result)
    tc.diff_offset = diff_offset

    if match:
        tc.result = TestResult.PASS
    else:
        struct_match, struct_msg = compare_code_signature(test_file, apple_result)
        if struct_match:
            tc.result = TestResult.FAIL
            tc.error_message = f"Structural match but byte diff: {msg}"
        else:
            tc.result = TestResult.FAIL
            tc.error_message = f"Signature mismatch: {struct_msg}; {msg}"

    return tc


def build_goblin_tool(project_root: Path) -> Optional[Path]:
    """Build the goblin-ext install_name_tool example."""
    print("Building goblin-ext install_name_tool...")
    result = subprocess.run(
        ["cargo", "build", "--release", "--example", "install_name_tool", "--features", "codesign"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Failed to build: {result.stderr}")
        return None

    tool_path = project_root / "target" / "release" / "examples" / "install_name_tool"
    if tool_path.exists():
        return tool_path
    return None


def run_all_tests(goblin_tool: Path, verbose: bool = False, keep_temp: bool = False,
                  strict: bool = False):
    """Run all code signing tests.

    Args:
        strict: If True, require bit-for-bit identical output with Apple's codesign.
                If False (default), pass if signatures are structurally equivalent.
    """
    results = []

    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)

        # Try to use pre-built assets first
        assets_dir = get_prebuilt_assets()
        test_bins = []

        if assets_dir:
            print(f"Using pre-built assets from: {assets_dir}")

            # Copy assets to temp directory for testing
            exe = copy_asset_to_temp(assets_dir, "test_exe_linker_signed", tmpdir)
            if exe:
                test_bins.append(("executable", exe))

            dylib = copy_asset_to_temp(assets_dir, "libtest_linker_signed.dylib", tmpdir)
            if dylib:
                test_bins.append(("dylib", dylib))

            # Note: Fat (universal) binaries are not yet supported by adhoc_sign
            # fat = copy_asset_to_temp(assets_dir, "test_exe_fat", tmpdir)
            # if fat:
            #     test_bins.append(("fat_binary", fat))
        else:
            # Fall back to compiling test binaries
            print("Creating test binaries (no pre-built assets found)...")

            exe = create_test_binary(tmpdir, "test_exe", is_dylib=False)
            if exe:
                test_bins.append(("executable", exe))

            dylib = create_test_binary(tmpdir, "test", is_dylib=True)
            if dylib:
                test_bins.append(("dylib", dylib))

        if not test_bins:
            print("ERROR: Could not create any test binaries")
            return 1

        print(f"Testing with {len(test_bins)} binary/binaries")
        if strict:
            print("Mode: STRICT (requiring bit-for-bit compatibility)")
        else:
            print("Mode: Structural equivalence (signatures must be functionally identical)")
        print()

        total_passed = 0
        total_failed = 0
        total_skipped = 0
        total_errors = 0

        for bin_type, binary_path in test_bins:
            print(f"Testing {bin_type}: {binary_path.name}")

            # Use a consistent identifier for comparison
            identifier = f"com.test.{binary_path.stem}"

            # Create a working directory for this binary
            work_dir = tmpdir / f"work_{binary_path.stem}"
            work_dir.mkdir(exist_ok=True)

            # Test 1: Basic ad-hoc signing
            tc = test_adhoc_signing(goblin_tool, binary_path, work_dir, identifier,
                                   hardened_runtime=False, verbose=verbose, strict=strict)
            results.append(tc)

            if tc.result == TestResult.PASS:
                total_passed += 1
                status = "PASS"
            elif tc.result == TestResult.FAIL:
                total_failed += 1
                status = "FAIL"
            elif tc.result == TestResult.SKIP:
                total_skipped += 1
                status = "SKIP"
            else:
                total_errors += 1
                status = "ERROR"

            print(f"  [{status}] {tc.name}")
            if tc.error_message and (tc.result != TestResult.PASS or verbose):
                print(f"       {tc.error_message}")
            if tc.result == TestResult.FAIL:
                print(f"       Sizes: goblin={tc.goblin_size}, apple={tc.apple_size}")
                if tc.diff_offset is not None:
                    print(f"       First diff at offset: 0x{tc.diff_offset:x}")

            # Test 2: Ad-hoc signing with hardened runtime
            work_dir2 = tmpdir / f"work_{binary_path.stem}_hardened"
            work_dir2.mkdir(exist_ok=True)

            tc = test_adhoc_signing(goblin_tool, binary_path, work_dir2, identifier,
                                   hardened_runtime=True, verbose=verbose, strict=strict)
            results.append(tc)

            if tc.result == TestResult.PASS:
                total_passed += 1
                status = "PASS"
            elif tc.result == TestResult.FAIL:
                total_failed += 1
                status = "FAIL"
            elif tc.result == TestResult.SKIP:
                total_skipped += 1
                status = "SKIP"
            else:
                total_errors += 1
                status = "ERROR"

            print(f"  [{status}] {tc.name}")
            if tc.error_message and (tc.result != TestResult.PASS or verbose):
                print(f"       {tc.error_message}")
            if tc.result == TestResult.FAIL:
                print(f"       Sizes: goblin={tc.goblin_size}, apple={tc.apple_size}")

            print()

        # Summary
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"  Passed:  {total_passed}")
        print(f"  Failed:  {total_failed}")
        print(f"  Skipped: {total_skipped}")
        print(f"  Errors:  {total_errors}")
        if not strict and total_passed > 0:
            print()
            print("Note: Tests passed with structural equivalence.")
            print("For bit-for-bit compatibility, run with --strict")
        print()

        if keep_temp:
            # Copy temp dir somewhere permanent
            import time
            keep_dir = Path(f"/tmp/codesign_test_{int(time.time())}")
            shutil.copytree(tmpdir, keep_dir)
            print(f"Temp files kept at: {keep_dir}")

        return 1 if (total_failed > 0 or total_errors > 0) else 0


def main():
    parser = argparse.ArgumentParser(
        description="Test goblin-ext ad-hoc code signing against Apple's codesign"
    )
    parser.add_argument(
        "--goblin-tool",
        type=Path,
        default=None,
        help="Path to goblin-ext's install_name_tool binary",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep temporary files for inspection",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require bit-for-bit identical output (default: structural equivalence)",
    )

    args = parser.parse_args()

    # Check we're on macOS
    if sys.platform != "darwin":
        print("This test only runs on macOS")
        sys.exit(1)

    # Build or find the goblin tool
    goblin_tool = args.goblin_tool
    if goblin_tool is None:
        script_dir = Path(__file__).parent
        project_root = script_dir.parent.parent
        goblin_tool = build_goblin_tool(project_root)
        if goblin_tool is None:
            print("Error: Could not build goblin-ext install_name_tool")
            sys.exit(1)

    if not goblin_tool.exists():
        print(f"Error: Goblin tool not found at {goblin_tool}")
        sys.exit(1)

    print(f"Using goblin tool: {goblin_tool}")
    print()

    exit_code = run_all_tests(goblin_tool, args.verbose, args.keep_temp, args.strict)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
