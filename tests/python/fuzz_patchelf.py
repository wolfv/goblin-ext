#!/usr/bin/env python3
"""
Fuzzing script for patchelf implementation.
Tests against shared libraries from:
- Standard Linux directories
- Conda packages from rattler cache
"""

import os
import sys
import subprocess
import tempfile
import shutil
import random
import argparse
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Tuple
import tarfile
import json
import time

# ANSI colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
RESET = "\033[0m"

@dataclass
class TestResult:
    library_path: str
    test_type: str
    success: bool
    error_message: Optional[str] = None
    byte_identical: Optional[bool] = None
    executes: Optional[bool] = None
    unsupported: bool = False  # True if this is a known unsupported case (PIE relocation)
    orig_patchelf_failed: bool = False  # True if original patchelf also failed

def find_elf_files(directory: str, extensions: List[str] = None) -> List[str]:
    """Find ELF files in a directory."""
    if extensions is None:
        extensions = ['.so', '.so.*']

    elf_files = []
    try:
        for root, dirs, files in os.walk(directory):
            # Skip some problematic directories
            skip_dirs = ['.git', 'node_modules', '__pycache__']
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file in files:
                filepath = os.path.join(root, file)
                # Check if it looks like a shared library
                if '.so' in file or file.endswith('.so'):
                    if os.path.isfile(filepath) and not os.path.islink(filepath):
                        # Verify it's actually an ELF file
                        try:
                            with open(filepath, 'rb') as f:
                                magic = f.read(4)
                                if magic == b'\x7fELF':
                                    elf_files.append(filepath)
                        except (IOError, PermissionError):
                            pass
    except PermissionError:
        pass

    return elf_files

def find_linux_libraries() -> List[str]:
    """Find shared libraries in standard Linux directories."""
    linux_dirs = [
        '/usr/lib',
        '/usr/lib64',
        '/usr/lib/x86_64-linux-gnu',
        '/lib',
        '/lib64',
        '/lib/x86_64-linux-gnu',
    ]

    libraries = []
    for directory in linux_dirs:
        if os.path.isdir(directory):
            print(f"  Scanning {directory}...")
            libs = find_elf_files(directory)
            libraries.extend(libs)
            print(f"    Found {len(libs)} libraries")

    return libraries

def find_conda_libraries(cache_dir: str) -> List[str]:
    """Find shared libraries in conda/rattler cache packages."""
    libraries = []

    if not os.path.isdir(cache_dir):
        print(f"  Cache directory not found: {cache_dir}")
        return libraries

    # Look for extracted packages
    pkgs_dir = os.path.join(cache_dir, 'pkgs')
    if os.path.isdir(pkgs_dir):
        print(f"  Scanning {pkgs_dir}...")
        for pkg_name in os.listdir(pkgs_dir):
            pkg_path = os.path.join(pkgs_dir, pkg_name)
            if os.path.isdir(pkg_path):
                libs = find_elf_files(pkg_path)
                libraries.extend(libs)
        print(f"    Found {len(libraries)} libraries in extracted packages")

    # Also check for .tar.bz2 or .conda files and extract temporarily
    # Look in the main cache directory
    for subdir in os.listdir(cache_dir):
        subdir_path = os.path.join(cache_dir, subdir)
        if os.path.isdir(subdir_path) and subdir != 'pkgs':
            # Check for package archives
            for item in os.listdir(subdir_path):
                item_path = os.path.join(subdir_path, item)
                if os.path.isdir(item_path):
                    # This might be an extracted package
                    libs = find_elf_files(item_path)
                    libraries.extend(libs)

    return libraries

def get_current_rpath(filepath: str) -> Optional[str]:
    """Get current RPATH/RUNPATH from an ELF file."""
    try:
        result = subprocess.run(
            ['readelf', '-d', filepath],
            capture_output=True,
            text=True,
            timeout=10
        )
        for line in result.stdout.split('\n'):
            if 'RPATH' in line or 'RUNPATH' in line:
                # Extract the path from brackets
                if '[' in line and ']' in line:
                    start = line.index('[') + 1
                    end = line.index(']')
                    return line[start:end]
        return None
    except Exception:
        return None

def run_patchelf_test(
    rust_patchelf: str,
    original_patchelf: str,
    library_path: str,
    test_type: str,
    new_rpath: str,
    work_dir: str
) -> TestResult:
    """Run a single patchelf test comparing rust vs original."""

    lib_name = os.path.basename(library_path)
    rust_input = os.path.join(work_dir, f"{lib_name}.rust_in")
    rust_output = os.path.join(work_dir, f"{lib_name}.rust")
    orig_output = os.path.join(work_dir, f"{lib_name}.orig")

    try:
        # Copy library for both tools
        shutil.copy2(library_path, rust_input)
        shutil.copy2(library_path, orig_output)

        # Rust patchelf uses: command <input> <output> [args]
        # Original patchelf uses: --flag [args] <file> (modifies in place)
        if test_type == "remove":
            rust_cmd = [rust_patchelf, 'remove-rpath', rust_input, rust_output]
            orig_cmd = [original_patchelf, '--remove-rpath', orig_output]
        else:
            rust_cmd = [rust_patchelf, 'set-rpath', rust_input, rust_output, new_rpath]
            orig_cmd = [original_patchelf, '--set-rpath', new_rpath, orig_output]

        # Run rust version
        rust_result = subprocess.run(
            rust_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Run original patchelf
        orig_result = subprocess.run(
            orig_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Check for known unsupported case: PIE binaries needing relocation
        is_pie_unsupported = (
            rust_result.returncode != 0 and
            "lowest virtual address" in rust_result.stderr and
            "too low" in rust_result.stderr
        )

        if rust_result.returncode != 0:
            return TestResult(
                library_path=library_path,
                test_type=test_type,
                success=False,
                error_message=f"Rust patchelf failed: {rust_result.stderr.strip()}",
                unsupported=is_pie_unsupported,
                orig_patchelf_failed=(orig_result.returncode != 0)
            )

        if orig_result.returncode != 0:
            return TestResult(
                library_path=library_path,
                test_type=test_type,
                success=False,
                error_message=f"Original patchelf failed: {orig_result.stderr}",
                orig_patchelf_failed=True
            )

        # Compare outputs
        with open(rust_output, 'rb') as f:
            rust_bytes = f.read()
        with open(orig_output, 'rb') as f:
            orig_bytes = f.read()

        byte_identical = rust_bytes == orig_bytes

        # Check if the library can still be loaded (basic sanity check)
        executes = True
        try:
            result = subprocess.run(
                ['readelf', '-h', rust_output],
                capture_output=True,
                timeout=5
            )
            executes = result.returncode == 0
        except Exception:
            executes = False

        if not byte_identical:
            # Find first difference
            diff_offset = None
            for i in range(min(len(rust_bytes), len(orig_bytes))):
                if rust_bytes[i] != orig_bytes[i]:
                    diff_offset = i
                    break
            if diff_offset is None and len(rust_bytes) != len(orig_bytes):
                diff_offset = min(len(rust_bytes), len(orig_bytes))

            return TestResult(
                library_path=library_path,
                test_type=test_type,
                success=False,
                error_message=f"Output differs at byte {diff_offset} (rust size: {len(rust_bytes)}, orig size: {len(orig_bytes)})",
                byte_identical=False,
                executes=executes
            )

        return TestResult(
            library_path=library_path,
            test_type=test_type,
            success=True,
            byte_identical=True,
            executes=executes
        )

    except subprocess.TimeoutExpired:
        return TestResult(
            library_path=library_path,
            test_type=test_type,
            success=False,
            error_message="Timeout"
        )
    except Exception as e:
        return TestResult(
            library_path=library_path,
            test_type=test_type,
            success=False,
            error_message=str(e)
        )
    finally:
        # Cleanup
        for f in [rust_input, rust_output, orig_output]:
            try:
                os.remove(f)
            except Exception:
                pass

def generate_test_rpaths(current_rpath: Optional[str]) -> List[Tuple[str, str]]:
    """Generate test cases for rpath modification."""
    tests = []

    if current_rpath:
        # Shorter rpath
        tests.append(("shorter", "/usr"))
        # Same length (approximately)
        if len(current_rpath) > 5:
            tests.append(("same_length", "X" * len(current_rpath)))
        # Longer rpath
        tests.append(("longer", "/very/long/path/that/requires/growth/and/relocation"))
        # Empty rpath
        tests.append(("empty", ""))
        # Remove rpath
        tests.append(("remove", ""))
    else:
        # No current rpath, add one
        tests.append(("add_short", "/usr/lib"))
        tests.append(("add_long", "/very/long/path/that/requires/growth/and/relocation"))

    return tests

def fuzz_library(
    rust_patchelf: str,
    original_patchelf: str,
    library_path: str,
    work_dir: str,
    verbose: bool = False
) -> List[TestResult]:
    """Run all fuzz tests on a single library."""
    results = []

    current_rpath = get_current_rpath(library_path)
    test_cases = generate_test_rpaths(current_rpath)

    for test_type, new_rpath in test_cases:
        result = run_patchelf_test(
            rust_patchelf,
            original_patchelf,
            library_path,
            test_type,
            new_rpath,
            work_dir
        )
        results.append(result)

        if verbose:
            if result.success:
                status = f"{GREEN}PASS{RESET}"
            elif result.unsupported:
                status = f"{YELLOW}UNSUPPORTED{RESET}"
            else:
                status = f"{RED}FAIL{RESET}"
            print(f"    {test_type}: {status}")
            if not result.success and result.error_message and not result.unsupported:
                print(f"      Error: {result.error_message}")

    return results

def main():
    parser = argparse.ArgumentParser(description="Fuzz test patchelf implementation")
    parser.add_argument(
        "--rust-patchelf",
        default="./target/debug/examples/patchelf",
        help="Path to rust patchelf binary"
    )
    parser.add_argument(
        "--original-patchelf",
        default="patchelf",
        help="Path to original patchelf binary"
    )
    parser.add_argument(
        "--conda-cache",
        default=os.path.expanduser("~/.cache/rattler/cache"),
        help="Path to conda/rattler cache directory"
    )
    parser.add_argument(
        "--max-libraries",
        type=int,
        default=100,
        help="Maximum number of libraries to test"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=4,
        help="Number of parallel workers"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--linux-only",
        action="store_true",
        help="Only test Linux system libraries"
    )
    parser.add_argument(
        "--conda-only",
        action="store_true",
        help="Only test conda libraries"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for library selection"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file for results (JSON)"
    )

    args = parser.parse_args()

    # Verify patchelf binaries exist
    if not os.path.isfile(args.rust_patchelf):
        print(f"{RED}Error: Rust patchelf not found at {args.rust_patchelf}{RESET}")
        print("Run: cargo build --example patchelf")
        sys.exit(1)

    try:
        subprocess.run([args.original_patchelf, '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}Error: Original patchelf not found or not working{RESET}")
        sys.exit(1)

    print(f"{BLUE}=== Patchelf Fuzzing Test ==={RESET}")
    print(f"Rust patchelf: {args.rust_patchelf}")
    print(f"Original patchelf: {args.original_patchelf}")
    print()

    # Collect libraries
    libraries = []

    print(f"{BLUE}Collecting libraries...{RESET}")

    if not args.conda_only:
        print("Linux system libraries:")
        linux_libs = find_linux_libraries()
        libraries.extend(linux_libs)
        print(f"  Total: {len(linux_libs)} libraries")

    if not args.linux_only:
        print("Conda/Rattler cache libraries:")
        conda_libs = find_conda_libraries(args.conda_cache)
        libraries.extend(conda_libs)
        print(f"  Total: {len(conda_libs)} libraries")

    # Remove duplicates (by inode)
    seen_inodes = set()
    unique_libraries = []
    for lib in libraries:
        try:
            stat = os.stat(lib)
            inode = (stat.st_dev, stat.st_ino)
            if inode not in seen_inodes:
                seen_inodes.add(inode)
                unique_libraries.append(lib)
        except Exception:
            pass

    libraries = unique_libraries
    print(f"\n{BLUE}Total unique libraries: {len(libraries)}{RESET}")

    if not libraries:
        print(f"{RED}No libraries found to test{RESET}")
        sys.exit(1)

    # Sample if too many
    if args.seed is not None:
        random.seed(args.seed)

    if len(libraries) > args.max_libraries:
        libraries = random.sample(libraries, args.max_libraries)
        print(f"Sampled {args.max_libraries} libraries for testing")

    print()
    print(f"{BLUE}Running tests...{RESET}")

    all_results = []
    passed = 0
    failed = 0
    unsupported = 0

    with tempfile.TemporaryDirectory() as work_dir:
        start_time = time.time()

        for i, library in enumerate(libraries):
            lib_name = os.path.basename(library)
            print(f"[{i+1}/{len(libraries)}] Testing {lib_name}...")

            results = fuzz_library(
                args.rust_patchelf,
                args.original_patchelf,
                library,
                work_dir,
                verbose=args.verbose
            )

            all_results.extend(results)
            lib_passed = sum(1 for r in results if r.success)
            lib_unsupported = sum(1 for r in results if not r.success and r.unsupported)
            lib_failed = sum(1 for r in results if not r.success and not r.unsupported)
            passed += lib_passed
            failed += lib_failed
            unsupported += lib_unsupported

            if not args.verbose:
                status_parts = []
                if lib_failed > 0:
                    status_parts.append(f"{RED}{lib_failed} failed{RESET}")
                if lib_unsupported > 0:
                    status_parts.append(f"{YELLOW}{lib_unsupported} unsupported{RESET}")
                if lib_passed > 0:
                    status_parts.append(f"{GREEN}{lib_passed} passed{RESET}")
                print(f"  {', '.join(status_parts)}")

        elapsed = time.time() - start_time

    # Summary
    print()
    print(f"{BLUE}=== Summary ==={RESET}")
    print(f"Libraries tested: {len(libraries)}")
    print(f"Total tests: {passed + failed + unsupported}")
    print(f"Passed: {GREEN}{passed}{RESET}")
    print(f"Unsupported (PIE relocation): {YELLOW}{unsupported}{RESET}")
    print(f"Failed: {RED}{failed}{RESET}")
    print(f"Time: {elapsed:.1f}s")

    if failed > 0:
        print()
        print(f"{RED}Actual failures (need investigation):{RESET}")
        for result in all_results:
            if not result.success and not result.unsupported:
                print(f"  {result.library_path}")
                print(f"    Type: {result.test_type}")
                print(f"    Error: {result.error_message}")
                if result.orig_patchelf_failed:
                    print(f"    Note: Original patchelf also failed")

    if unsupported > 0 and args.verbose:
        print()
        print(f"{YELLOW}Unsupported cases (PIE binaries needing relocation):{RESET}")
        for result in all_results:
            if not result.success and result.unsupported:
                print(f"  {result.library_path} ({result.test_type})")

    # Save results to JSON if requested
    if args.output:
        results_data = {
            "summary": {
                "libraries_tested": len(libraries),
                "total_tests": passed + failed + unsupported,
                "passed": passed,
                "unsupported": unsupported,
                "failed": failed,
                "elapsed_seconds": elapsed
            },
            "results": [
                {
                    "library": r.library_path,
                    "test_type": r.test_type,
                    "success": r.success,
                    "unsupported": r.unsupported,
                    "error": r.error_message,
                    "byte_identical": r.byte_identical,
                    "executes": r.executes,
                    "orig_patchelf_failed": r.orig_patchelf_failed
                }
                for r in all_results
            ]
        }
        with open(args.output, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"\nResults saved to {args.output}")

    # Only fail if there are actual failures (not unsupported cases)
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
