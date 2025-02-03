#include <stdio.h>
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
 * vulnerable_print() performs the vulnerable printf call.
 * It is marked with __attribute__((noinline)) to prevent inlining, thereby
 * ensuring a fresh stack frame is created for each call.
 *
 * CRITICAL VULNERABILITY:
 * Using printf(buffer) here lets the buffer (which contains format specifiers)
 * be interpreted as a format string. In real applications, such behavior may allow
 * an attacker to read or write arbitrary memory.
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
         * If a segmentation fault occurs during the vulnerable call, the signal
         * handler will longjmp here (returning a non-zero value) to allow the loop
         * to continue. Note: This may lead to memory leaks because the allocated
         * buffer from the current iteration might not be freed.
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
         *   - "%x" prints data interpreted as an unsigned int (often from the stack).
         *   - "%p" prints pointer/address values.
         */
        const char *pattern = "%x %p ";
        size_t pattern_len = strlen(pattern);

        for (size_t offset = 0; offset < current_size - 1; offset += pattern_len) {
            size_t remaining = (current_size - 1) - offset;
            size_t to_copy = (remaining < pattern_len) ? remaining : pattern_len;
            memcpy(&buffer[offset], pattern, to_copy);
        }
        buffer[current_size - 1] = '\0';

        // Print summary and a partial preview of the buffer
        printf("Buffer preview (first 50 chars): %.50s\n", buffer);
        printf("Printing buffer (vulnerable):\n");

        /* 
         * Instead of calling printf(buffer) directly in main (which uses the main() stack frame),
         * we call vulnerable_print() so that each iteration uses a new stack frame.
         * This helps ensure that the memory values printed (which come from the stack)
         * vary from iteration to iteration.
         */
        vulnerable_print(buffer);

        // -----------------------------------------------------------------------
        // Print insightful analysis of the results for this iteration.
        // -----------------------------------------------------------------------
        printf("Analysis:\n");
        printf("  - The printed memory values are extracted from the stack frame of the function 'vulnerable_print()'.\n");
        printf("  - Since vulnerable_print() is called as a separate function (and not inlined), its stack frame\n");
        printf("    is freshly allocated each time. This typically results in different memory values being printed\n");
        printf("    across iterations, reflecting variations in the stack layout.\n");
        printf("  - If the values appear constant, it may indicate compiler optimizations or a very stable stack layout,\n");
        printf("    which can be an important insight for an attacker or a security researcher.\n");
        printf("  - This behavior underscores the risk inherent in format string vulnerabilities: even benign-looking\n");
        printf("    code can inadvertently leak memory content.\n");

        printf("--------------------------------------------------\n\n");

        // Cleanup: free the allocated memory for this iteration
        free(buffer);

        // Prepare for the next iteration: increase buffer size and iteration count
        iteration++;
        current_size += STEP_SIZE;
    }

    printf("Vulnerable format string test complete.\n");
    return 0;
}