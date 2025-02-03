#!/usr/bin/env python3
import subprocess
import time
import os
import signal
import re
import statistics
import argparse

def analyze_scan_output(output: str) -> str:
    """
    Analyzes the raw scan output from the vulnerable C scanner and produces
    actionable insights. In addition to the basic statistics, the analysis now
    includes:

      - Total iterations run.
      - Count and ratio of segmentation fault recoveries.
      - Detailed statistics about the allocated buffer sizes (average, median,
        standard deviation, and range).
      - Extraction and comprehensive statistical analysis of hex addresses,
        including average, median, standard deviation, and overall range.
      - Identification of frequently repeated hex addresses (threshold > 10 times)
        which may indicate a stable or reserved memory region.
      - Warnings if the distribution of addresses is unusually narrow or if the
        ratio of segmentation faults to iterations is high.
      
    This detailed analysis helps in understanding both the memory layout changes
    during the vulnerable printing and the behavior of the scanner in response to
    segmentation faults.
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
            insights.append("Insufficient data for advanced allocation statistics.")
    else:
        insights.append("No allocation size data found.")

    # -------------------------------
    # 4. Hexadecimal Address Analysis
    # -------------------------------
    # Extract hex addresses (e.g., "0x7ffdfc3a2b60")
    hex_addresses = re.findall(r'0x[0-9a-fA-F]+', output)
    if hex_addresses:
        # Convert hex addresses to integers for statistical analysis
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

            # Also report the overall range of hex addresses.
            min_addr = min(unique_addresses)
            max_addr = max(unique_addresses)
            insights.append(f"Hex address range: 0x{min_addr:016x} - 0x{max_addr:016x}")
            # Warn if the range is too narrow (e.g., less than 4KB difference).
            if (max_addr - min_addr) < 0x1000:
                insights.append("Warning: Hex addresses are within a narrow range (less than 4KB), "
                                "which may indicate a stable memory region or limited stack variation.")
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
    # Identify addresses that appear more than 10 times.
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
    # Warn if segmentation faults occur in more than 30% of the iterations.
    if num_iterations > 0 and (num_segfaults / num_iterations) > 0.3:
        insights.append("Warning: High frequency of segmentation faults detected. This may indicate unstable memory operations.")
    else:
        insights.append("Segmentation fault frequency appears within expected limits.")

    # Combine all insights into a single report string.
    analysis_report = "\n".join(insights)
    return analysis_report

def main():
    # The following C code implements a vulnerable format string scanner.
    # It intentionally uses an insecure printf call (with user-controlled format string)
    # and deliberately creates variations in the stack layout using a dummy volatile array.
    # The purpose is to demonstrate how format string vulnerabilities can leak stack memory
    # contents (e.g., hex addresses) and how segmentation faults can be recovered from.
    c_code = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>    // For signal handling
#include <setjmp.h>    // For non-local jump recovery

#define INITIAL_SIZE   1024         // Start with a 1 KB buffer
#define STEP_SIZE      (1024*2)     // Increase by 2 KB each iteration

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
 * vulnerable_print() performs the dangerous printf call.
 * It is marked with __attribute__((noinline)) to ensure that each call
 * uses a fresh stack frame. (WARNING: Using printf(buffer) is insecure.)
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

    /* 
     * The dangerous call: any format specifiers in buffer are interpreted,
     * reading (or even writing) memory from the stack.
     */
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
 * It allocates a volatile dummy array whose content depends on the iteration
 * number. This helps to ensure that each call to vulnerable_print() sees a
 * different stack state.
 */
void smart_scan(const char *buffer, unsigned long iteration) {
    volatile char dummy[128];
    for (size_t i = 0; i < sizeof(dummy); i++) {
        dummy[i] = (char)((iteration + i) & 0xFF);
    }
    vulnerable_print(buffer);
}

int main(void) {
    // Set up signal handler for segmentation fault
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    printf("Starting vulnerable format string test in an infinite loop...\n\n");

    unsigned long iteration = 0;
    size_t current_size = INITIAL_SIZE;

    while (1) {
        /* 
         * Set a recovery point.
         * If a segmentation fault occurs during the vulnerable call,
         * the signal handler will longjmp here (returning a non-zero value)
         * to allow the loop to continue.
         */
        if (setjmp(env) != 0) {
            printf("Recovered from segmentation fault. Continuing to next iteration...\n\n");
            iteration++;
            current_size += STEP_SIZE;
            continue;
        }

        printf("Iteration %lu:\n", iteration);
        printf("Allocating %zu bytes\n", current_size);

        // Allocate the buffer for this iteration
        char *buffer = (char *)malloc(current_size);
        if (!buffer) {
            fprintf(stderr, "Failed to allocate %zu bytes (iteration %lu): %s\n",
                    current_size, iteration, strerror(errno));
            break;
        }

        /*
         * Fill the buffer with a repeated malicious pattern.
         *   - "%x" prints an unsigned int from the stack.
         *   - "%p" prints a pointer/address.
         */
        const char *pattern = "%x %p ";
        size_t pattern_len = strlen(pattern);
        for (size_t offset = 0; offset < current_size - 1; offset += pattern_len) {
            size_t remaining = (current_size - 1) - offset;
            size_t to_copy = (remaining < pattern_len) ? remaining : pattern_len;
            memcpy(&buffer[offset], pattern, to_copy);
        }
        buffer[current_size - 1] = '\0';

        // Print a brief preview of the buffer and then call the vulnerable print routine
        printf("Buffer preview (first 50 chars): %.50s\n", buffer);
        printf("Printing buffer (vulnerable):\n");

        // Use smart_scan() to force a new stack layout before the vulnerable call.
        smart_scan(buffer, iteration);

        // -----------------------------------------------------------------------
        // Print insightful analysis of the results for this iteration.
        // -----------------------------------------------------------------------
        printf("Analysis:\n");
        printf("  - The printed memory values come from the stack frame of 'vulnerable_print()'.\n");
        printf("  - By using 'smart_scan()', we allocate a volatile dummy array whose values vary\n");
        printf("    with the iteration number. This causes a change in the stack layout so that the\n");
        printf("    memory addresses and data printed (via %%x and %%p) vary from one iteration to the next.\n");
        printf("  - If the output still appears constant, compiler optimizations or a stable stack region may be\n");
        printf("    responsible. This highlights the subtle and dangerous nature of format string vulnerabilities.\n");
        printf("--------------------------------------------------\n\n");

        // Cleanup: free the allocated memory for this iteration
        free(buffer);

        // Prepare for the next iteration
        iteration++;
        current_size += STEP_SIZE;
    }

    printf("Vulnerable format string test complete.\n");
    return 0;
}
'''

    # Write the C code to file
    c_filename = "vulnerable_scanner.c"
    with open(c_filename, "w") as f:
        f.write(c_code)

    # Compile the C code with optimizations turned off (-O0) to help preserve stack differences.
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

    # Run the compiled scanner.
    # (Since the C program loops forever, we let it run for 10 seconds and then terminate it.)
    print("\nRunning the vulnerable scanner for 10 seconds. (You can adjust the sleep time as desired.)\n")
    proc = subprocess.Popen(["./vulnerable_scanner"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass

    print("\nTerminating the vulnerable scanner...")
    os.kill(proc.pid, signal.SIGTERM)
    stdout, _ = proc.communicate()
    print("Raw scanner output:")
    print(stdout)

    # Now analyze the scan results using our advanced analysis routine.
    print("\nPerforming advanced analysis of the scan results...\n")
    analysis_report = analyze_scan_output(stdout)
    print("Advanced Analysis Report:")
    print("-------------------------------------")
    print(analysis_report)
    print("-------------------------------------")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Machine Learning Red Team Exploit Code")
    parser.add_argument("--exploit", action="store_true", help="Execute exploit code on authorized containers.")
    args = parser.parse_args()

    if args.exploit:
        main()
    else:
        print("Exploit flag not set. To run the exploit, use the '--exploit' flag.")