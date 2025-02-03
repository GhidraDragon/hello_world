#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>  // For backtrace functionality

/*
 * This program progressively allocates larger strings,
 * fills them with malicious format specifiers (like %x and %p),
 * then passes them **directly** to printf with no fixed format string.
 *
 * WARNING: Calling printf(buffer) with uncontrolled format specifiers
 * is a true format-string vulnerability. In production code, always use
 * a fixed format string (e.g. printf("%s", buffer)) to avoid such vulnerabilities.
 *
 * This demo intentionally leaves the vulnerability unmitigated to show how
 * format string attacks can be exploited to leak memory information.
 * (If "%n" were allowed, it could even enable arbitrary memory writes.)
 *
 * For additional vulnerability insights, a signal handler for SIGSEGV is installed.
 * When a segmentation fault occurs, the handler prints a backtrace to help diagnose
 * the fault, which might occur when the format string leads to invalid memory access.
 *
 * Adjust MAX_ITERATIONS and STEP_SIZE to stress test more.
 * This is extremely unsafe in real scenarios.
 */

#define MAX_ITERATIONS 5          // How many different sizes to try
#define INITIAL_SIZE   1024       // Start with a 1 KB buffer
#define STEP_SIZE      (1024*1024)  // Increase by 1 MB each iteration

// Signal handler for segmentation faults to print a backtrace.
void segfault_handler(int sig) {
    void *array[20];
    size_t size;

    fprintf(stderr, "\n*** Caught signal %d (%s) ***\n", sig, strsignal(sig));
    size = backtrace(array, 20);
    fprintf(stderr, "Backtrace (%zu frames):\n", size);
    char **symbols = backtrace_symbols(array, size);
    if (symbols) {
        for (size_t i = 0; i < size; i++) {
            fprintf(stderr, "[%zu] %s\n", i, symbols[i]);
        }
        free(symbols);
    }
    exit(EXIT_FAILURE);
}

int main(void) {
    // Register the segmentation fault handler to print a backtrace on crash.
    signal(SIGSEGV, segfault_handler);

    printf("Starting vulnerable format string test...\n\n");

    // Array to store allocated buffers so that pointers aren’t lost.
    char *buffers[MAX_ITERATIONS] = {0};

    // Print the address of a local variable to provide insight into the stack layout.
    int dummy = 0;
    printf("Address of dummy variable (on stack): %p\n\n", (void*)&dummy);

    // Loop through multiple iterations, increasing the buffer size each time.
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        // Calculate size for this iteration.
        size_t current_size = INITIAL_SIZE + (i * STEP_SIZE);

        // Allocate the buffer.
        buffers[i] = (char *)malloc(current_size);
        if (!buffers[i]) {
            fprintf(stderr, "Failed to allocate %zu bytes (iteration %d): %s\n",
                    current_size, i, strerror(errno));
            continue;
        }

        // Debug: Print the pointer address of the allocated buffer.
        printf("Iteration %d: Buffer allocated at address %p\n", i, (void*)buffers[i]);
        printf("Allocated %zu bytes for iteration %d\n", current_size, i);

        // Fill the buffer with a repeated malicious pattern.
        // The pattern contains format specifiers "%x" and "%p" which, when passed
        // as a format string, will leak stack data (e.g., memory addresses and values).
        // Note: The dangerous "%n" specifier is intentionally omitted to avoid immediate crashes.
        const char *pattern = "%x %p ";
        size_t pattern_len = strlen(pattern);

        for (size_t offset = 0; offset < current_size - 1; offset += pattern_len) {
            size_t remaining = (current_size - 1) - offset;
            size_t to_copy = (remaining < pattern_len) ? remaining : pattern_len;
            memcpy(&buffers[i][offset], pattern, to_copy);
        }
        buffers[i][current_size - 1] = '\0';

        // Print a preview of the buffer and a separator for clarity.
        printf("Buffer preview (first 50 chars): %.50s\n", buffers[i]);
        printf("--------------------------------------------------\n");

        /*
         * VULNERABLE USAGE:
         * The following call to printf() is dangerous because it uses the contents of
         * buffers[i] as the format string. This means that any format specifiers
         * (like %x or %p) inside the buffer will be interpreted by printf() and
         * can leak information about the process's memory.
         *
         * In a real-world exploit, an attacker who controls the buffer could tailor
         * the format string to disclose memory contents or even write to arbitrary
         * memory locations if the "%n" specifier were used.
         */
        #if defined(__clang__)
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wformat-security"
        #elif defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wformat-security"
        #endif

        printf("Printing buffer (vulnerable):\n");
        // DANGEROUS: The following call interprets the malicious pattern as a format string.
        printf(buffers[i]);
        printf("\n");

        #if defined(__clang__)
        #pragma clang diagnostic pop
        #elif defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif

        printf("--------------------------------------------------\n\n");
    }

    // Cleanup: free allocated memory.
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        if (buffers[i]) {
            free(buffers[i]);
            buffers[i] = NULL;
        }
    }

    printf("Vulnerable format string test complete.\n");
    return 0;
}
