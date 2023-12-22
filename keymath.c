/*
Developed by Luis Alberto Updated by Adam
email: alberto.bsd@gmail.com
gcc -o keymath keymath.c -lgmp
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "util.h"
#include "hashtable.h"
#include <pthread.h>
#include <signal.h>

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];
struct publickey
{
	char *key; // Store the public key as a string
};
struct hashmap *publicKeysMap;

const char *version = "0.1.211009";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const char *formats[3] = {"publickey", "rmd160", "address"};
const char *looks[2] = {"compress", "uncompress"};

uint64_t publickey_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
	const struct publickey *key = item;
	return hashmap_sip(key->key, strlen(key->key), seed0, seed1);
}

int publickey_compare(const void *a, const void *b, void *udata)
{
	const struct publickey *ka = a;
	const struct publickey *kb = b;
	return strcmp(ka->key, kb->key);
}

void set_publickey(char *param, struct Point *publickey);
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);
void loadPublicKeysIntoHashTable(struct hashmap *publicKeysMap)
{
	FILE *file = fopen("publickeys.txt", "r");
	if (!file)
	{
		fprintf(stderr, "Error opening publickeys.txt\n");
		return;
	}

	char fileKey[256];
	while (fgets(fileKey, sizeof(fileKey), file))
	{
		fileKey[strcspn(fileKey, "\n")] = 0; // Remove newline character
		char *dynamicKey = strdup(fileKey);	 // Duplicate the string
		if (dynamicKey)
		{
			struct publickey newKey = {.key = dynamicKey};
			hashmap_set(publicKeysMap, &newKey);
		}
	}

	fclose(file);
}

char *str_output = NULL;
char *str_input = NULL;
char *str_publickey_ptr = NULL;

char str_publickey[132];
char str_rmd160[41];
char str_address[41];

struct Point A, B, C;

int FLAG_NUMBER = 0;

mpz_t inversemultiplier, number, increment, original_number, random_min, random_max;
bool random_mode = false;
gmp_randstate_t state;

FILE *matchedKeysFile;

bool checkPublicKey(struct hashmap *publicKeysMap, const char *generatedKey)
{
	struct publickey key = {.key = (char *)generatedKey};
	return hashmap_get(publicKeysMap, &key) != NULL;
}

void generate_random_number(mpz_t result, mpz_t min, mpz_t max, gmp_randstate_t state)
{
	// Check if min < max, if not, return an error or handle appropriately
	if (mpz_cmp(min, max) >= 0)
	{
		// Handle error: min should be less than max
		fprintf(stderr, "Error: min should be less than max in generate_random_number.\n");
		return;
	}

	static mpz_t range;
	static bool is_initialized = false;

	// Initialize range only once
	if (!is_initialized)
	{
		mpz_init(range);
		is_initialized = true;
	}

	mpz_sub(range, max, min);			// range = max - min
	mpz_urandomm(result, state, range); // Generate random number in [0, range)
	mpz_add(result, result, min);		// Shift to [min, max)
}

// Remember to clear the static variable when it's no longer needed, e.g., at the end of your program
void clear_random_number_generator()
{
	mpz_clear(range);
}

void handle_sigint(int sig)
{
	printf("Caught signal %d, cleaning up and exiting\n", sig);

	// Clear mpz variables
	mpz_clears(EC.p, EC.n, G.x, G.y, A.x, A.y, B.x, B.y, C.x, C.y, range, number, inversemultiplier, original_number, random_min, random_max, NULL);

	// Close the matched keys file
	if (matchedKeysFile != NULL)
	{
		fclose(matchedKeysFile);
		matchedKeysFile = NULL;
	}

	// Clear the random state
	gmp_randclear(state);

	// Destroy the hash table
	if (publicKeysMap != NULL)
	{
		hashmap_free(publicKeysMap);
		publicKeysMap = NULL;
	}

	exit(0); // Exit program
}

int main(int argc, char **argv)
{
	bool continue_mode = false;
	bool random_mode = false;
	mpz_t random_min, random_max;
	mpz_init(random_min);
	mpz_init(random_max);

	gmp_randstate_t state;				// Declare the random state variable
	gmp_randinit_default(state);		// Initialize the random state
	gmp_randseed_ui(state, time(NULL)); // Seed the random state
	signal(SIGINT, handle_sigint);

	int hashTableSize = 35000000;
	struct hashmap *publicKeysMap = hashmap_new(sizeof(struct publickey), 0, 0, 0, publickey_hash, publickey_compare, NULL, NULL);

	if (!publicKeysMap)
	{
		fprintf(stderr, "Failed to create hashmap.\n");
		return 1;
	}

	loadPublicKeysIntoHashTable(publicKeysMap);

	FILE *matchedKeysFile = fopen("matched_keys.txt", "a");
	if (matchedKeysFile == NULL)
	{
		fprintf(stderr, "Error opening matched_keys.txt\n");
		return 1;
	}

	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x, EC_constant_Gx, 16);
	mpz_init_set_str(G.y, EC_constant_Gy, 16);
	init_doublingG(&G);

	mpz_init_set_ui(A.x, 0);
	mpz_init_set_ui(A.y, 0);
	mpz_init_set_ui(B.x, 0);
	mpz_init_set_ui(B.y, 0);
	mpz_init_set_ui(C.x, 0);
	mpz_init_set_ui(C.y, 0);
	mpz_init(number);
	mpz_init(inversemultiplier);
	mpz_init(original_number);

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-m") == 0)
		{
			continue_mode = true;
		}
		else if (strcmp(argv[i], "-R") == 0)
		{
			random_mode = true;
			if (i + 1 < argc)
			{
				char *token = strtok(argv[i + 1], ":");
				if (token != NULL)
				{
					mpz_set_str(random_min, token, 10);
					token = strtok(NULL, ":");
					if (token != NULL)
					{
						mpz_set_str(random_max, token, 10);
					}
					else
					{
						fprintf(stderr, "Error: missing max value for -R option\n");
						return 1;
					}
				}
				else
				{
					fprintf(stderr, "Error: missing range for -R option\n");
					return 1;
				}
			}
			else
			{
				fprintf(stderr, "Error: missing -R argument\n");
				return 1;
			}
		}
	}

	if (argc < 4)
	{
		printf("Missing parameters\n");
		exit(0);
	}

	switch (strlen(argv[1]))
	{
	case 66:
	case 130:
		set_publickey(argv[1], &A);
		break;
	default:
		printf("Unknown public key length\n");
		exit(0);
	}

	switch (strlen(argv[3]))
	{
	case 66:
		if (argv[3][0] == '0' && argv[3][1] == 'x')
		{
			mpz_set_str(number, argv[3], 0);
			FLAG_NUMBER = 1;
		}
		else
		{
			set_publickey(argv[3], &B);
			FLAG_NUMBER = 0;
		}
		break;
	case 130:
		set_publickey(argv[3], &B);
		FLAG_NUMBER = 0;
		break;
	default:
		mpz_set_str(number, argv[3], 0);
		FLAG_NUMBER = 1;
		break;
	}

	mpz_mod(number, number, EC.n);
	mpz_set(original_number, number);

	do
	{
		if (random_mode)
		{
			generate_random_number(number, random_min, random_max, state); // Use the state
			mpz_mod(number, number, EC.n);
		}

		switch (argv[2][0])
		{
		case '+':
			if (FLAG_NUMBER)
			{
				Scalar_Multiplication(G, &B, number);
			}
			Point_Addition(&A, &B, &C);
			break;
		case '-':
			if (FLAG_NUMBER)
			{
				Scalar_Multiplication(G, &B, number);
			}
			Point_Negation(&B, &C);
			mpz_set(B.x, C.x); // Update B.x with C.x
			mpz_set(B.y, C.y); // Update B.y with C.y
			Point_Addition(&A, &B, &C);
			break;
		case '/':
			if (!FLAG_NUMBER)
			{
				printf("Cannot divide two public keys, need a scalar number\n");
				exit(0);
			}
			mpz_invert(inversemultiplier, number, EC.n);
			Scalar_Multiplication_custom(A, &C, inversemultiplier);
			break;
		case 'x':
			if (!FLAG_NUMBER)
			{
				printf("Cannot multiply two public keys, need a scalar number\n");
				exit(0);
			}
			Scalar_Multiplication_custom(A, &C, number);
			break;
		}

		generate_strpublickey(&C, true, str_publickey);
		gmp_fprintf(stdout, "\r%s # - %Zd", str_publickey, number);
		fflush(stdout); // Ensure the output is updated immediately

		if (checkPublicKey(publicKeysMap, str_publickey))
		{
			gmp_fprintf(matchedKeysFile, "%s # - %Zd\n", str_publickey, number);
			printf("\nMatching key found: %s\n", str_publickey);
			break;
		}

		if (continue_mode && !random_mode)
		{
			mpz_add(number, number, original_number);
		}
	} while (continue_mode);

	mpz_clears(EC.p, EC.n, G.x, G.y, A.x, A.y, B.x, B.y, C.x, C.y, number, inversemultiplier, original_number, random_min, random_max, NULL);
	fclose(matchedKeysFile);
	gmp_randclear(state); // Clear the random state at the end
	hashmap_free(publicKeysMap);
	return 0;
}

void generate_strpublickey(struct Point *publickey, bool compress, char *dst)
{
	memset(dst, 0, 131);
	if (compress)
	{
		if (mpz_tstbit(publickey->y, 0) == 0)
		{ // Even
			gmp_snprintf(dst, 67, "02%0.64Zx", publickey->x);
		}
		else
		{
			gmp_snprintf(dst, 67, "03%0.64Zx", publickey->x);
		}
	}
	else
	{
		gmp_snprintf(dst, 131, "04%0.64Zx%0.64Zx", publickey->x, publickey->y);
	}
}

void set_publickey(char *param, struct Point *publickey)
{
	char hexvalue[65];
	char *dest;
	int len;
	len = strlen(param);
	dest = (char *)calloc(len + 1, 1);
	if (dest == NULL)
	{
		fprintf(stderr, "[E] Error calloc\n");
		exit(0);
	}
	memset(hexvalue, 0, 65);
	memcpy(dest, param, len);
	trim(dest, " \t\n\r");
	len = strlen(dest);
	switch (len)
	{
	case 66:
		mpz_set_str(publickey->x, dest + 2, 16);
		break;
	case 130:
		memcpy(hexvalue, dest + 2, 64);
		mpz_set_str(publickey->x, hexvalue, 16);
		memcpy(hexvalue, dest + 66, 64);
		mpz_set_str(publickey->y, hexvalue, 16);
		break;
	}
	if (mpz_cmp_ui(publickey->y, 0) == 0)
	{
		mpz_t mpz_aux, mpz_aux2, Ysquared;
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux, publickey->x, 3);
		mpz_add_ui(mpz_aux2, mpz_aux, 7);
		mpz_mod(Ysquared, mpz_aux2, EC.p);
		mpz_add_ui(mpz_aux, EC.p, 1);
		mpz_fdiv_q_ui(mpz_aux2, mpz_aux, 4);
		mpz_powm(publickey->y, Ysquared, mpz_aux2, EC.p);
		mpz_sub(mpz_aux, EC.p, publickey->y);
		switch (dest[1])
		{
		case '2':
			if (mpz_tstbit(publickey->y, 0) == 1)
			{
				mpz_set(publickey->y, mpz_aux);
			}
			break;
		case '3':
			if (mpz_tstbit(publickey->y, 0) == 0)
			{
				mpz_set(publickey->y, mpz_aux);
			}
			break;
		default:
			fprintf(stderr, "[E] Some invalid bit in the publickey: %s\n", dest);
			exit(0);
			break;
		}
		mpz_clear(mpz_aux);
		mpz_clear(mpz_aux2);
		mpz_clear(Ysquared);
	}
	free(dest);
}

void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m)
{
	struct Point Q, T;
	long no_of_bits, loop;
	mpz_init(Q.x);
	mpz_init(Q.y);
	mpz_init(T.x);
	mpz_init(T.y);
	no_of_bits = mpz_sizeinbase(m, 2);
	mpz_set_ui(R->x, 0);
	mpz_set_ui(R->y, 0);
	if (mpz_cmp_ui(m, 0) != 0)
	{
		mpz_set(Q.x, P.x);
		mpz_set(Q.y, P.y);
		if (mpz_tstbit(m, 0) == 1)
		{
			mpz_set(R->x, P.x);
			mpz_set(R->y, P.y);
		}
		for (loop = 1; loop < no_of_bits; loop++)
		{
			Point_Doubling(&Q, &T);
			mpz_set(Q.x, T.x);
			mpz_set(Q.y, T.y);
			mpz_set(T.x, R->x);
			mpz_set(T.y, R->y);
			if (mpz_tstbit(m, loop))
				Point_Addition(&T, &Q, R);
		}
	}
	mpz_clear(Q.x);
	mpz_clear(Q.y);
	mpz_clear(T.x);
	mpz_clear(T.y);
}
