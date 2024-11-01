#include "aes-128_enc.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>      
#include <unistd.h>

// Q.1
uint8_t my_xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x7B;

	return ((p << 1) ^ m);
}

// Q.2
/*
* AES-128 (Nk=4, Nr=10)
* Key 000102030405060708090a0b0c0d0e0f
*/

void print_tab(uint8_t* t , int len){
    for(int i = 0 ; i < len; i++){
        printf("%02X", t[i]);
    }
    printf("\n");
}

int copy(uint8_t * t_src , uint8_t * t_des , int l){
    for(int j = 0 ; j < l ; j ++){
        t_des[j] = t_src[j];
    }
    return 0;
}
int q_2_test() {
    uint8_t next_key[AES_128_KEY_SIZE];
    uint8_t prev_key[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    printf("round[%02d].k_ch  ", 0);
    print_tab(prev_key, AES_128_KEY_SIZE);
    for(int r = 0; r < 10 ; r++ ){
        next_aes128_round_key(prev_key, next_key,r);
        copy(next_key, prev_key ,AES_128_KEY_SIZE);
        printf("round[%02d].k_ch  ", r+1);
        print_tab(prev_key, AES_128_KEY_SIZE);
    }
    printf("------------------  Inverse   ------------------\n");
    
    printf("round[%02d].k_ch  ", 10);
    print_tab(next_key, AES_128_KEY_SIZE);
    for(int r = 9; r >= 0 ; --r ){
        prev_aes128_round_key(next_key, prev_key,r);
        copy(prev_key, next_key ,AES_128_KEY_SIZE);
        printf("round[%02d].k_ch  ", r);
        print_tab(next_key, AES_128_KEY_SIZE);
    }

    return 0;
}

/*
* Q.3 : Build a keyed function F
*/

int aes_keyed_function(uint8_t aes_block[AES_BLOCK_SIZE], uint8_t key1[AES_128_KEY_SIZE], uint8_t key2[AES_128_KEY_SIZE]) {
    uint8_t b1[AES_BLOCK_SIZE];
    uint8_t b2[AES_BLOCK_SIZE];
    copy(aes_block, b1, AES_BLOCK_SIZE);
    copy(aes_block, b2, AES_BLOCK_SIZE);
    aes128_enc(b1, key1 , 3 , 1);
    aes128_enc(b2, key2 , 3 , 1);
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        aes_block[i] = b1[i] ^ b2[i];
    }
    return 0;
}

int q_3_test() {
    printf("---------------  keyed function  ---------------\n");
    uint8_t aes_block[AES_BLOCK_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t key1[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t key2[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t key3[AES_128_KEY_SIZE] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t block[AES_BLOCK_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    printf("input :  ");
    print_tab(aes_block, AES_BLOCK_SIZE);
    aes_keyed_function(aes_block, key1, key2);
    printf("output : if k1 = k2 : ");
    print_tab(aes_block, AES_BLOCK_SIZE);
    printf("output : if k1 =! k2 : ");
    aes_keyed_function(block, key1, key3);
    print_tab(block, AES_BLOCK_SIZE);
    return 0;
}

int is_false_positive(uint8_t t[256][AES_128_KEY_SIZE]) {
    for(int i = 0; i < AES_BLOCK_SIZE; i++){
        int s = 0;
        for(int j = 0; j < 256; j++){
            s+= t[i][j];
            if(s >= 2){
                return 1;
            }
        }
    }
    return 0;
}

// Generates a random AES-128 key using /dev/urandom
void generate_random_key(uint8_t key[AES_128_KEY_SIZE]) {
    // Open /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    // Read 16 bytes 
    ssize_t result = read(fd, key, AES_128_KEY_SIZE);
    
    if (result < 0) {
        perror("Failed to read from /dev/urandom");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

/**
 *  exo 2, question 1
 */
int attack_aes() {
    uint16_t nb_blocks = 256;
    uint8_t nb_sets = 3;
    uint8_t key[AES_128_KEY_SIZE]; 
    generate_random_key(key); // generete the key

    uint8_t found_key[AES_128_KEY_SIZE] = {0};     
    uint8_t tmp_key[AES_128_KEY_SIZE] = {0};    
    uint8_t lambda_set[nb_sets][nb_blocks][AES_BLOCK_SIZE];  
   

    printf("The real AES key generated randomly: ");
    print_tab(key, AES_128_KEY_SIZE);
    printf("Searching for AES key...\n");

    /* generete lambda sets */
    for (uint8_t set = 0; set < nb_sets; set++){
        for (uint16_t i = 0; i < nb_blocks; i++) {
            lambda_set[set][i][0] = i;
            for (uint8_t j = 1; j < 16; j++) {
                lambda_set[set][i][j] = 0x00+set;
            }
            aes128_enc(lambda_set[set][i], key, 4, 0);
        }
    }

    // Update guessed_key based on sum criterion
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        for (int k = 0; k < nb_blocks; k++) {
            uint8_t distinguisher[nb_sets];
            memset(distinguisher, 0, sizeof(distinguisher));
            for (uint8_t set = 0; set < nb_sets; set++){
                for (int j = 0; j < nb_blocks; j++) {
                    uint8_t b = lambda_set[set][j][i] ^ k;
                    uint8_t binv = Sinv[b];  // Inverse S-box lookup
                    distinguisher[set] ^= binv;
                }
                if(distinguisher[set] != 0){
                    break;
                };
            }
            if(distinguisher[0] == 0 && distinguisher[1] == 0 && distinguisher[2] == 0){
                found_key[i] = k;
                break;
            } 
        }
    }

    // Perform key schedule inversion to retrieve the original AES-128 master key
    prev_aes128_round_key(found_key, tmp_key, 3);
    prev_aes128_round_key(tmp_key, found_key, 2);
    prev_aes128_round_key(found_key, tmp_key, 1);
    prev_aes128_round_key(tmp_key, found_key, 0);

    printf("AES master key found: ");
    print_tab(found_key, AES_128_KEY_SIZE);
    printf("\n");

    return 0;
}

/**
 *  exo 2 , quest 2:
 */
int ex2_q2(){

    uint8_t key[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t block[AES_BLOCK_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t b2[AES_BLOCK_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    printf("************* ciphering with default xtime and Shift tables S/Sinv \n");
    printf("plaintext :  ");
    print_tab(block, AES_BLOCK_SIZE);
    printf("key:  ");
    print_tab(key, AES_128_KEY_SIZE);
    aes128_enc(block, key, 4, 0);
    printf("ciphertext :  ");
    print_tab(block, AES_BLOCK_SIZE);
    printf("************* ciphering with new version of xtime and Shift table \n");
    SWITCH ^= 1 ; // change xtime
    generate_Sb(S); // change S/Sinv
    generate_invSb(S, Sinv);
    printf("plaintext :  ");
    print_tab(b2, AES_BLOCK_SIZE);
    printf("key:  ");
    print_tab(key, AES_128_KEY_SIZE);
    aes128_enc(b2, key, 4, 0);
    printf("ciphertext :  ");
    print_tab(b2, AES_BLOCK_SIZE);
    printf("************* square attack with new version of S/Sinv and xtime \n");
    int k = attack_aes();
    assert(k == 0);
    return 0;
}


int main() {
    printf("** part 1 : Q2  =========================================================== \n");
    int i = q_2_test();
    assert(i == 0);
    printf("** part 1 : Q3  =========================================================== \n");
    int j = q_3_test();
    assert(j == 0);
    printf(" \n");
    printf("** part 2 : Q1  =========================================================== \n");
    int k = attack_aes();
    assert(k == 0);
    printf("** part 2 : Q2  =========================================================== \n");
    k = ex2_q2();
    assert(k == 0);
    return 0;

}