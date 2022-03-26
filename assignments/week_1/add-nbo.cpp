#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

u_int32_t reverse(u_int32_t x) {
    u_int32_t res = 0;
    u_int32_t byte;

    for(int i = 0; i < 4; i++) {
        byte = x >> (i * 8) & 0xFF;
        res <<= 8;
        res |= byte;
    }

    return res;
}

// 4 byte size(uint) num in file, read file and add num, print result
int main(int argc, char *argv[]){\
    FILE *num_1, *num_2;

    if(argc != 3){
        printf("Usage: %s <num1> <num2>\n", argv[0]);
        return 1;
    }

    num_1 = fopen(argv[1], "r");
    num_2 = fopen(argv[2], "r");

    if(num_1 == NULL || num_2 == NULL){
        printf("File open error\n");
        return 1;
    }

    uint32_t num1, num2;
    fread(&num1, sizeof(uint32_t), 1, num_1);
    fread(&num2, sizeof(uint32_t), 1, num_2);

    num1 = reverse(num1);
    num2 = reverse(num2);

    int result = num1 + num2;

    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",num1, num1, num2, num2, result, result);

    fclose(num_1);
    fclose(num_2);

    return 0;
}