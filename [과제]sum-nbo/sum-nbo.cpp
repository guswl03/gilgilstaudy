//ai 돌리면 나오는 코드 주석 달아보기
#include <cstdio> //입출력 함수
#include <cstdint> //uint32_t를 사용하기위해
#include <arpa/inet.h> //네트워크 바이트 순서 변환 함수 사용

int main(int argc, char* argv[]) { //argc : 인자 개수 , argv : 인자로 전달된 문자 열 배열
    //인자가 1개 이상 입력되었는지 확인
    if (argc < 2) {
        printf("syntax : sum-nbo <file1> [<file2>...]\n");
        printf("sample : sum-nbo a.bin b.bin c.bin\n");
        return 1;
    } // 예시

    uint32_t sum = 0; // 파일에서 읽어온 32비트 정수들의 합 저장하는 변수

//입력받은 파일 개수만큼 반복
    for (int i = 1; i < argc; i++) { //i 번재 인자로 받은 파일명을 이진 읽기모드
        FILE* file = fopen(argv[i], "rb");

        if (file == nullptr) { //실패한경우
            fprintf(stderr, "cannot open file: %s\n", argv[i]); //에러 메세지 출력
            return 1;
        }

        uint32_t networkNumber; //파일에서 읽은 4바이트 값을 저장하는 변수

        // 파일에서 4바이트 크기 1개를 읽음
        // 개수가 1이 아니면 애러발생
        if (fread(&networkNumber, sizeof(networkNumber), 1, file) != 1) {
            fprintf(stderr, "cannot read 4 bytes: %s\n", argv[i]);
            fclose(file);
            return 1;
        }

        fclose(file); // 읽기 정상 완료 시 파일 닫기

        uint32_t hostNumber = ntohl(networkNumber); // 파이트 순서를 호스트로 B -> L

        if (i > 1) { // 처번째 파일이 아니면 덧셈 출력
            printf(" + ");
        }

        printf("%u(0x%08x)", hostNumber, hostNumber); // 변환된 값 10진주 및 16진수 형식으로 출력
        sum += hostNumber;
    }

    printf(" = %u(0x%08x)\n", sum, sum); // 최종 합계 10진수 및 16진수로 변환 출력 줄바꿈
    return 0;
}
