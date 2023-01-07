#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>
#include <string.h>

gmp_randstate_t state;

//This function creates parts of a new RSA Public key, which include two large primes and their product n and their public exponent e.
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {

    uint64_t pbits = rand() % (2 * nbits) / 4;

    pbits += nbits / 4;

    //Creating two large primes p and q
    make_prime(p, pbits + 1, iters);
    make_prime(q, nbits - pbits + 1, iters);

    //Creating n by multiplying p and q
    mpz_mul(n, p, q);

    //Computing φ(n)
    mpz_t p_minus_one, q_minus_one, totient, e_gcd;
    mpz_inits(p_minus_one, q_minus_one, totient, e_gcd, NULL);
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_sub_ui(q_minus_one, q, 1);
    mpz_mul(totient, p_minus_one, q_minus_one);

    //Computing e
    while (mpz_cmp_ui(e_gcd, 1) != 0) {
        //I literally have no clue why my totient variable becomes 0, so I constantly compute it.
        mpz_mul(totient, p_minus_one, q_minus_one);
        mpz_urandomb(e, state, nbits);
        gcd(e_gcd, e, totient);
    }

    //I literally have no clue why my n variable becomes 0, so I constantly compute it.
    mpz_mul(n, p, q);

    mpz_clears(p_minus_one, q_minus_one, totient, e_gcd, NULL);
    return;
}

void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile,
        "%Zx\n"
        "%Zx\n"
        "%Zx\n"
        "%s\n",
        n, e, s, username);
}

void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile,
        "%Zx\n"
        "%Zx\n"
        "%Zx\n"
        "%s\n",
        n, e, s, username);
}

void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {

    mpz_t p_minus_one, q_minus_one, totient;
    mpz_inits(p_minus_one, q_minus_one, totient, NULL);

    //Creating the totient again
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_sub_ui(q_minus_one, q, 1);
    mpz_mul(totient, p_minus_one, q_minus_one);

    //Finding d
    mod_inverse(d, e, totient);

    mpz_clears(p_minus_one, q_minus_one, totient, NULL);
}

void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile,
        "%Zx\n"
        "%Zx\n",
        n, d);
}

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile,
        "%Zx\n"
        "%Zx\n",
        n, d);
}

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {

    mpz_t m, c;
    mpz_inits(m, c, NULL);
    uint64_t bytes_read;

    //Calculating block size k
    uint64_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    //Dynamically allocating the block using k as the size
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t *));

    //Prepending 0xFF to the zeroth byte of the block to place the work around.
    block[0] = 0xFF;

    //Reading k-1 bytes from infile and adding the amount of bytes read to bytes_read until the EOF is reached.
    while (feof(infile) == 0) {

        bytes_read = fread(block + 1, sizeof(uint8_t), k - 1, infile);

        //Converting the read bytes including hte 0xFF into an mpz_t.
        mpz_import(m, bytes_read + 1, 1, sizeof(uint8_t), 1, 0, block);

        //Creating the encrypted number
        rsa_encrypt(c, m, e, n);

        //Printing out the number to an outfile as a hexstring.
        gmp_fprintf(outfile, "%Zx\n", c);
    }
    //Clearing the mpz variables.
    mpz_clears(m, c, NULL);
    free(block);
}

void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {

    //Creating variables for function
    mpz_t m, c;
    mpz_inits(m, c, NULL);
    uint64_t bytes_read;

    //Calculating block size k
    uint64_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    //Dynamically allocating the block using k as the size
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t *));

    //Insert comment
    while (feof(infile) == 0) {
        //Scan in the number from an infile as a hexstring.
        gmp_fscanf(infile, "%Zx\n", c);

        //Decrypting c and storing back into m
        rsa_decrypt(m, c, d, n);

        //Insert Comment
        mpz_export(block, &bytes_read, 1, sizeof(uint8_t), 1, 0, m);

        //Writing the the decrypted data to an outfile
        fwrite(block + 1, sizeof(uint8_t), bytes_read - 1, outfile);
    }
    //Clearing the mpz variables.
    mpz_clears(m, c, NULL);
    free(block);
}

void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t v;
    mpz_init(v);
    pow_mod(v, s, e, n);
    if (mpz_cmp(m, v) == 0) {
        mpz_clear(v);
        return true;
    }
    mpz_clear(v);
    return false;
}
