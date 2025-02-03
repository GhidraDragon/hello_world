// vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A global stable variable controlling privilege.
int admin = 0;

/*
 * vulnerable_print() uses printf without a format string check.
 * This allows an attacker to inject format specifiers into the output.
 */
void vulnerable_print(char *user_input) {
    // Vulnerable: user_input is used directly as the format string.
    printf(user_input);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char buffer[256];
    
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        exit(1);
    }
    
    // Copy user input to buffer (for demonstration only—this is insecure).
    strncpy(buffer, argv[1], sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    vulnerable_print(buffer);

    // Check if the admin flag was set by the attacker.
    if (admin) {
        printf("Access granted! You are now admin.\n");
    } else {
        printf("Access denied! You are not admin.\n");
    }
    
    return 0;
}