#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gmp.h>

/****************************************************/
// Filename: keygen.c
// Created: Dylan Do
/****************************************************/

void help(); //Declaration for the help function.

int main(int argc, char **argv) {

    //Creating variables needed for keygen
    int opt = 0;
    FILE *pbfile = fopen("rsa.pub", "w");
    FILE *pvfile = fopen("rsa.priv", "w");
    uint64_t nbits = 256;
    uint64_t iters = 50;
    uint64_t seed = (uint64_t) time(NULL);
    char *username = getenv("USER");
    bool verbose = false;

    //This while loop is responsible for parsing through the command-lines given by a user.
    while ((opt = getopt(argc, argv, "b:i:n:d:s:vh")) != -1) {

        //This if statement is responsible for printing out the help statement if the user inputs an unknown command-line.
        if (opt == '?') {
            help();
            fclose(pbfile);
            fclose(pvfile);
            return -1;
        }

        //This are all the cases.
        switch (opt) {
        case 'v': verbose = true; break;
        case 'h':
            help();
            fclose(pbfile);
            fclose(pvfile);
            return -1;
        case 'b': nbits = atoi(optarg); break;
        case 'i': iters = atoi(optarg); break;
        case 'n': pbfile = fopen(optarg, "w"); break;
        case 'd': pvfile = fopen(optarg, "w"); break;
        case 's': seed = atoi(optarg); break;
        }
    }

    //Sets the file permissions
    fchmod(fileno(pbfile), 0600);
    fchmod(fileno(pvfile), 0600);

    //initializes the random seed
    randstate_init(seed);
    srand(seed);

    //Creating and initializing mpz variables
    mpz_t p, q, n, e, d, s, username_mpz;
    mpz_inits(p, q, n, e, d, s, username_mpz, NULL);

    //Making the public and private key
    rsa_make_pub(p, q, n, e, nbits, iters);
    rsa_make_priv(d, e, p, q);

    //Converting the username to mpz
    mpz_set_str(username_mpz, username, 62);

    //Signing the username
    rsa_sign(s, username_mpz, d, n);

    //Writing the public and private infor to their respective files.
    rsa_write_pub(n, e, s, username, pbfile);
    rsa_write_priv(n, d, pvfile);

    //Prints out the verbose if indicated by user.
    if (verbose) {
        printf("user = %s\n", username);
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("p (%zu bits) = %Zd\n", mpz_sizeinbase(p, 2), p);
        gmp_printf("q (%zu bits) = %Zd\n", mpz_sizeinbase(q, 2), q);
        gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("d (%zu bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    //Clearing all memory.
    mpz_clears(p, q, n, e, d, s, username_mpz, NULL);
    randstate_clear();
    fclose(pbfile);
    fclose(pvfile);
}

//Helper function that prints out the help statement.
void help() {
    printf("SYNOPSIS\n");
    printf("   Generates an RSA public/private key pair.\n");
    printf("\n");
    printf("USAGE\n");
    printf("   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("   -h              Display program help and usage.\n");
    printf("   -v              Display verbose program output.");
    printf("   -b bits         Minimum bits needed for public key n\n");
    printf("   -c confidence   Miller-Rabin iterations for testing primes (default: 50).\n");
    printf("   -n pbfile       Public key file (default: rsa.pub).\n");
    printf("   -d pvfile       Private key file (default: rsa.priv).\n");
    printf("   -s seed         Random seed for testing.\n");
}

