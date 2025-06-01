#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    // Check usage
    if (argc != 2) {
        fprintf(stderr, "USAGE: %s keylength\n", argv[0]);
        return 1;
    }

    // Parse key length argument
    int keyLength = atoi(argv[1]);
    if (keyLength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer\n");
        return 1;
    }

    // Seed random number generator
    srand((unsigned int) time(NULL));

    for (int i = 0; i < keyLength; i++) {
        int r = rand() % 27;
        char c = (r == 26) ? ' ' : 'A' + r;
        putchar(c);
    }

    putchar('\n');

    return 0;
}
