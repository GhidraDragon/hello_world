#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * VULNERABLE FORMAT-STRING DEMO
 *
 * This program progressively allocates larger strings,
 * fills them with malicious format specifiers (like %x and %p),
 * then passes them **directly** to printf with no format string.
 *
 * WARNING: Calling printf(buffer) with uncontrolled format specifiers
 * is a genuine format-string vulnerability. It can allow attackers to:
 *   1) Read arbitrary memory (via %s, %p, %x, etc.),
 *   2) Potentially overwrite memory (via %n, or certain length specifiers),
 *   3) Crash the program (segmentation fault, or other memory violation),
 *   4) Possibly gain code execution (in more complex scenarios combined
 *      with other system-specific conditions).
 *
 * REMOVED "%n" SPECIFIER:
 *   - In many compilers/libc implementations, "%n" can write to memory,
 *     causing immediate or eventual crashes, or even code execution if
 *     an attacker carefully manipulates the memory. Here, we have removed
 *     "%n" so the program can run long enough to show how a malicious
 *     buffer might print out stack/heap pointers, addresses, or other
 *     system details when used by printf() incorrectly.
 *
 * KEY TAKEAWAY:
 *   Always use a fixed format string, e.g.:
 *       printf("%s", user_input);
 *   and never let user-controlled data be used directly as the
 *   format string. This sample intentionally ignores that rule
 *   to reveal the danger.
 *
 * ABOUT THIS DEMO:
 *   - The pattern "%x %p " is repeated throughout the buffer.
 *   - Each iteration uses a larger buffer (initially ~1KB, up to ~5MB).
 *   - Eventually, we often see a crash after printing some addresses,
 *     due to the massive volume of malicious format specifiers. On some
 *     systems, the program may keep going for a while, dumping many
 *     pointers and partial stack data to stdout.
 *
 *   If you experiment by adding "%n" back into 'pattern', you may see:
 *     - Immediate segmentation fault or bus error,
 *     - Overwrites of memory addresses, or
 *     - Behavior changes that can be harnessed by attackers
 *       in a real exploit scenario.
 *
 * COMPILATION AND RUNNING:
 *   - On some compilers, you might need to disable certain warnings:
 *       gcc -o vulnerable_test demo.c -Wno-format-security
 *   - Then run: ./vulnerable_test
 *   - You may see addresses/stack values, or the program might crash
 *     immediately, depending on system protections, ASLR, etc.
 *
 * NOTE: This is purely a demonstration of how dangerous it is to call
 *       printf() with a user-controlled format string. Do NOT deploy
 *       code like this in any real environment.
 */

#define MAX_ITERATIONS 5            // How many different sizes to try
#define INITIAL_SIZE   1024         // Start with a 1 KB buffer
#define STEP_SIZE      (1024*1024)  // Increase by 1 MB each iteration

int main(void) {
    printf("Starting vulnerable format string test...\n\n");

    // We'll store our allocated buffers in an array
    // to avoid losing references. Each iteration gets a new buffer.
    char *buffers[MAX_ITERATIONS] = {0};

    // Attempt to allocate and test each size in turn
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        // Calculate size for this iteration
        size_t current_size = INITIAL_SIZE + (i * STEP_SIZE);

        // Allocate the buffer
        buffers[i] = (char *)malloc(current_size);
        if (!buffers[i]) {
            fprintf(stderr, "Failed to allocate %zu bytes (iteration %d): %s\n",
                    current_size, i, strerror(errno));
            continue;
        }

        /*
         * Fill the buffer with a repeated malicious pattern.
         *   - "%x" prints data interpreted as an unsigned int (often from stack).
         *   - "%p" prints pointer/address values.
         * This effectively spam-prints uninitialized memory pointers and can
         * leak addresses that might help an attacker defeat ASLR or glean
         * sensitive data from memory if used within a privileged process.
         *
         * Since we're deliberately showing a vulnerability, we do not sanitize
         * anything here. In a real application, this is exactly what you do NOT do.
         *
         * If you reintroduce "%n", you might see memory corruption or a crash.
         */
        const char *pattern = "%x %p ";
        size_t pattern_len = strlen(pattern);

        for (size_t offset = 0; offset < current_size - 1; offset += pattern_len) {
            // Copy the pattern or as much as will fit into the remaining space.
            size_t remaining = (current_size - 1) - offset;
            size_t to_copy = (remaining < pattern_len) ? remaining : pattern_len;
            memcpy(&buffers[i][offset], pattern, to_copy);
        }
        buffers[i][current_size - 1] = '\0';

        // Print summary and partial preview
        printf("Iteration %d:\n", i);
        printf("Allocated %zu bytes for iteration %d\n", current_size, i);
        printf("Buffer preview (first 50 chars): %.50s\n", buffers[i]);

        // -----------------------------------------------------------------------
        // VULNERABLE USAGE: printing a raw buffer that contains %x, %p, etc.
        // -----------------------------------------------------------------------
        // For demonstration, we disable compiler warnings about format security.
        #if defined(__clang__)
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wformat-security"
        #elif defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wformat-security"
        #endif

        printf("Printing buffer (vulnerable):\n");

        /*
         * CRITICAL VULNERABILITY:
         * The line below calls printf(buffers[i]), letting the
         * malicious string inside buffers[i] be interpreted as
         * the format string. Attackers can:
         *   - read memory,
         *   - cause a crash,
         *   - or manipulate memory if "%n" or advanced specifiers are used.
         */
        printf(buffers[i]);
        printf("\n");

        #if defined(__clang__)
        #pragma clang diagnostic pop
        #elif defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif

        printf("--------------------------------------------------\n\n");
    }

    // Cleanup: free allocated memory
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        if (buffers[i]) {
            free(buffers[i]);
            buffers[i] = NULL;
        }
    }

    printf("Vulnerable format string test complete.\n");
    return 0;
}