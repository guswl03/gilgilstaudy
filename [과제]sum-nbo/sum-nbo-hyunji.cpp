//수기
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

int main(int argc, char* argv[])
{
    // 파일 없으면 종료
    if (argc < 2){
        printf("syntax : sum-nbo <file1> [<file2>...]\n");
        printf("sample : sum-nbo a.bin b.bin c.bin\n");
        return -1;
    }

    uint32_t total = 0;
    int i;

    for (i = 1; i < argc; i++) 
    {
        FILE *f = fopen(argv[i], "rb");
        if(f == NULL) {
            printf("cannot open file : %s\n", argv[i]);
            exit(1);
        }

        uint32_t buf;
        int res = fread(&buf, 4, 1, f);
        if (res != 1) {
            printf("file read error!! %s\n", argv[i]);
            fclose(f);
            return 1;
        }
        fclose(f);

        // 엔디안 변환
        uint32_t num = ntohl(buf);

        if (i != 1) {
            printf(" + ");
        }

        printf("%u(0x%x)", num, num);
        total += num; // 합하기
    }

    printf(" = %u(0x%x)\n", total, total);

    return 0;
}
