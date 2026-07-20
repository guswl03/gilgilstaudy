#include <cstdio>
#include <cstdint>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("syntax : sum-nbo <file1> [<file2>...]\n");
        printf("sample : sum-nbo a.bin b.bin c.bin\n");
        return 1;
    }

    uint32_t sum = 0;

    for (int i = 1; i < argc; i++) {
        FILE* file = fopen(argv[i], "rb");

        if (file == nullptr) {
            fprintf(stderr, "cannot open file: %s\n", argv[i]);
            return 1;
        }

        uint32_t networkNumber;

        if (fread(&networkNumber, sizeof(networkNumber), 1, file) != 1) {
            fprintf(stderr, "cannot read 4 bytes: %s\n", argv[i]);
            fclose(file);
            return 1;
        }

        fclose(file);

        uint32_t hostNumber = ntohl(networkNumber);

        if (i > 1) {
            printf(" + ");
        }

        printf("%u(0x%08x)", hostNumber, hostNumber);
        sum += hostNumber;
    }

    printf(" = %u(0x%08x)\n", sum, sum);
    return 0;
}
