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
// Filename: decrypt.c
// Created: Dylan Do
/****************************************************/

void help(); //Declaration for the help function.

int main(int argc, char **argv) {

    //Creating variables needed for encrypt
    int opt = 0;
    mpz_t n, d;
    mpz_inits(n, d, NULL);
    bool verbose = false;
    FILE *infile = stdin; //The infile responsble for being the input file. Set to stdin by default.
    FILE *outfile
        = stdout; //The outfile is responsible for being the output file. Set to stdout by default.
    char *pub = "rsa.priv";

    //This while loop is responsible for parsing through the command-lines given by a user.
    while ((opt = getopt(argc, argv, "i:o:n:vh")) != -1) {

        //This if statement is responsible for printing out the help statement if the user inputs an unknown command-line.
        if (opt == '?') {
            help();
            fclose(infile);
            fclose(outfile);
            return -1;
        }

        //This are all the cases.
        switch (opt) {
        case 'v': verbose = true; break;
        case 'h':
            help();
            fclose(infile);
            fclose(outfile);
            return -1;
        case 'i': infile = fopen(optarg, "r"); break;
        case 'o': outfile = fopen(optarg, "w"); break;
        case 'n': pub = optarg;
        }
    }

    FILE *pvfile = fopen(pub, "r");
    if (pvfile == NULL) {
        printf("Error, failed to open public key file.");
        return 1;
    }

    rsa_read_priv(n, d, pvfile);

    if (verbose) {
        gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    rsa_decrypt_file(infile, outfile, n, d);

    mpz_clears(n, d, NULL);
    fclose(infile);
    fclose(outfile);
    fclose(pvfile);
}

//Helper function that prints out the help statement.
void help() {
    printf("SYNOPSIS\n");
    printf("   Encrypts data using RSA encryption.\n");
    printf("   Encrypted data is decrypted by the decrypt program.\n");
    printf("\n");
    printf("USAGE\n");
    printf("   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("   -h              Display program help and usage.\n");
    printf("   -v              Display verbose program output.");
    printf("   -i infile       Input file of data to encrypt (default: stdin).\n");
    printf("   -o outfile      Output file for encrypted data (default: stdout).\n");
    printf("   -n pbfile       Public key file (default: rsa.pub).\n");
}

