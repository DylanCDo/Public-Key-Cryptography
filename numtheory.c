#include "numtheory.h"
#include "randstate.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>

gmp_randstate_t state;

//This function finds the greatest common divisor between a and b and stores it into g.
void gcd(mpz_t g, mpz_t a, mpz_t b) {

    //Creating temp variables
    mpz_t a_temp, b_temp;
    mpz_inits(a_temp, b_temp, NULL);
    mpz_set(a_temp, a);
    mpz_set(b_temp, b);

    //While b does not equal 0
    while (mpz_cmp_ui(b_temp, 0) != 0) {
        //Set g to b
        mpz_set(g, b_temp);
        //Finds a % b and sets it to b
        mpz_mod(b_temp, a_temp, b_temp);
        //Sets a to g
        mpz_set(a_temp, g);
    }
    //Sets g to a
    mpz_set(g, a_temp);

    //Clearing memory
    mpz_clears(a_temp, b_temp, NULL);
}

void mod_inverse(mpz_t o, mpz_t a, mpz_t n) {

    //Setting variables needed for the Euclidean algorithm
    mpz_t r, r_prime, t, t_prime, r_temp, t_temp, q_temp, q;
    mpz_inits(r, r_prime, t, t_prime, r_temp, t_temp, q_temp, q, NULL);

    //Setting the values of both r
    mpz_set(r, n);
    mpz_set(r_prime, a);

    //Setting the values of both t
    mpz_set_ui(t, 0);
    mpz_set_ui(t_prime, 1);

    //While r' does not equal 0
    while (mpz_cmp_ui(r_prime, 0) != 0) {
        mpz_fdiv_q(q, r, r_prime);

        mpz_set(r_temp, r);
        mpz_set(t_temp, t);

        mpz_mul(q_temp, q, r_prime);
        mpz_set(r, r_prime);
        mpz_sub(r_prime, r_temp, q_temp);

        mpz_mul(q_temp, q, t_prime);
        mpz_set(t, t_prime);
        mpz_sub(t_prime, t_temp, q_temp);
    }

    if (mpz_cmp_ui(t, 0) < 0) {
        mpz_add(t, t, n);
    }

    if (mpz_cmp_ui(r, 1) < 0 || mpz_cmp_ui(r, 1) == 0) {
        mpz_set(o, t);
    } else {
        mpz_set_ui(o, 0);
    }

    mpz_clears(r, r_prime, t, t_prime, r_temp, t_temp, q_temp, q, NULL);
}

//Performs modular exponjentiation and stores it into o.
void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {

    //Creating a variable p and setting it to a and a variable v and setting it to 1 (Also a temp variables for d and n)
    mpz_t p, v, d_temp, n_temp;
    mpz_inits(p, v, d_temp, n_temp, NULL);
    mpz_set(p, a);
    mpz_set(d_temp, d);
    mpz_set(n_temp, n);
    mpz_set_ui(v, 1);

    //While d is greater than 0
    while (mpz_cmp_ui(d_temp, 0) > 0) {
        //If d is odd
        if (mpz_odd_p(d_temp) != 0) {
            //Sets v to (v * p) % n
            mpz_mul(v, v, p);
            mpz_mod(v, v, n_temp);
            mpz_set(o, v);
        }
        //Sets p to (p *p) % n
        mpz_mul(p, p, p);
        mpz_mod(p, p, n_temp);

        //Sets d to d/2
        mpz_fdiv_q_ui(d_temp, d_temp, 2);
    }

    mpz_clears(p, v, d_temp, n_temp, NULL);
}

//This function implements the Miller-Rabin primality test to deterministically tests for a prime number.
bool is_prime(mpz_t n, uint64_t iters) {

    //If n is 2 or 3 return true
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) {
        return true;
    }

    //If n is 1 or n is even, return false
    if (mpz_cmp_ui(n, 1) == 0 || mpz_even_p(n) != 0) {
        return false;
    }

    //Creating variables needed for the miller rabin primality test and initializing them.
    mpz_t r, s, a, y, j, n_minus_one, n_minus_three, two, s_minus_one;
    mpz_inits(r, s, a, y, j, n_minus_one, n_minus_three, two, s_minus_one, NULL);

    //Setting r to n - 1
    mpz_sub_ui(r, n, 1);

    //Setting s to 0
    mpz_set_ui(s, 0);

    //Setting n_minus_one to n-1
    mpz_sub_ui(n_minus_one, n, 1);

    //Setting n_minus_three to n-3
    mpz_sub_ui(n_minus_three, n, 3);

    //Setting two to 2
    mpz_set_ui(two, 2);

    //Solving for s and r
    while (mpz_even_p(r) != 0) {
        mpz_add_ui(s, s, 1);
        mpz_div_ui(r, r, 2);
    }

    //Setting s_minus_one to s-1
    mpz_sub_ui(s_minus_one, s, 1);

    //for iters amount of time
    for (uint64_t i = 1; i < iters; i++) {
        //Setting a to a random number
        mpz_urandomm(a, state, n_minus_three);

        //Adding 2 to a to shift it into range (2, n-2)
        mpz_add_ui(a, a, 2);

        //Modular Expnontiation
        pow_mod(y, a, r, n);

        //If y does not equal 1 and does not equal n-1
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_minus_one) != 0) {
            //Setting j to 1
            mpz_set_ui(j, 1);

            //While j is less than or equal to s and y does not equal n - 1
            while (mpz_cmp(j, s_minus_one) <= 0 && (mpz_cmp(y, n_minus_one) != 0)) {
                //I literally have no clue why my two variable becomes 0, so I constantly set it to two.
                mpz_set_ui(two, 2);
                //Modular Expnontiation
                pow_mod(y, y, two, n);
                //if y equals 1
                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clears(r, s, a, y, j, n_minus_one, n_minus_three, two, s_minus_one, NULL);
                    return false;
                }
                //Adds 1 to j
                mpz_add_ui(j, j, 1);
            }
            //If y does not equal n minus 1
            if (mpz_cmp(y, n_minus_one) != 0) {
                mpz_clears(r, s, a, y, j, n_minus_one, n_minus_three, two, s_minus_one, NULL);
                return false;
            }
        }
    }
    mpz_clears(r, s, a, y, j, n_minus_one, n_minus_three, s_minus_one, two, NULL);
    return true;
}

//This function randomly finds a prime number that is bit long.
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {

    mpz_urandomb(p, state, bits);
    while (!(is_prime(p, iters)) || mpz_sizeinbase(p, 2) < bits) {
        mpz_urandomb(p, state, bits);
    }
}
