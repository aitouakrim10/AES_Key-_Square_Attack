#ifndef UTILES_H
#define UTILES_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>


extern uint8_t S[256];
extern uint8_t Sinv[256];




void swap(uint8_t* a, uint8_t* b);
// Function to generate a random S-Box by shuffling values from 0 to 255
void generate_Sb(uint8_t sbox[256]);
void generate_invSb(uint8_t sbox[256], uint8_t invsbox[256]);

#endif 
