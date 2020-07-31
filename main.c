#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include "sha256.h"

#define GROWTH_FACTOR 2

#define PWD4SHA256  "pwd4sha256"
#define PWD6SHA256  "pwd6sha256"
#define PWDXSHA256  "pwdXsha256"

#define DICT_FILE "dict.txt"

#define BRUTE_MODE 1
#define GUESS_MODE 2
#define TEST_MODE  3

#define LEN_PWD_MIN    4
#define LEN_PWD_MAX    6
#define CHAR_PWD_MIN  32
#define CHAR_PWD_MAX 126
#define MAX_SUBS       3

// remnants of an old brute force solution
#define NEXT_CHAR(C) (((((C) - CHAR_PWD_MIN + 1) % \
(CHAR_PWD_MAX - CHAR_PWD_MIN + 1)) + CHAR_PWD_MIN))
#define CARRIED_CHAR(C) ((C) == CHAR_PWD_MIN)

typedef struct {
	BYTE *hashes;
	int *done;
	int count;
} Hash;

typedef struct {
	char *word;
	int *index;
	int alloc;
} Word;

void test_passwords(char *pwd_filename, char *sha_filename);

int read_line(FILE *fp, Word *word);
void print_sha256(BYTE *hash);

void word_init(Word *word);
void word_free(Word *word);
void word_reset(Word *word, int min, const char *set);

void hash_init(Hash *hash, char *filename);
void hash_free(Hash *hash);

// generates up to count guesses if sha_filename is NULL, 
// else generates and checkes guesses against the hashes
void generate_guesses(long count, char *sha_filename);

// checks a word against a hash
void check_hash(Word *word, Hash *hash, int len);
// mutates word to be the next word in the set from offset
int next_set(Word *word, int offset, int max, const char *set, int set_len);
// guesses words in the DICT_FILE using a set
void guess_set_dict(Word *word, const char *set, long *remaining, Hash *hash);
// makes a guess. either prints or checks against hash
void make_guess(Word *word, int len, long *remaining, Hash *hash);
// guesses substitutions of words in the dictionary
void guess_subs(Word *word, long *remaining, Hash *hash);
// guesses and produces the next substituition for a word
void next_sub(Word *word, int len, int index, int n_subs, long *remaining, Hash *hash);

// various subsets of characters
static const char *letters = "abcdefghijklmnopqrstuvwxyz";
static const char *numbers = "0123456789";
// static const char *special = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static const char *full = " !\"#$%&'()*+,-./0123456789:;<=>?" \
                          "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_" \
                          "`abcdefghijklmnopqrstuvwxyz{|}~";

// substititutions for each character
static const char *subs[] = {
	"A@&", "B68", "C[(<", "D])>?", "E3", "F#", "G9", "H#", "I1|!",
	"J", "K<", "L7", "M", "N^", "O0*", "P?", "Q9", "R",
	"S5$2", "T+", "U", "V", "W", "X%", "Y", "Z2"
};

int main(int argc, char *argv[]) {

	switch (argc) {
	case BRUTE_MODE:
		// this one could take a very long time. which it did :(
		generate_guesses(-1, PWDXSHA256);
		break;
	case GUESS_MODE:
		generate_guesses(strtol(argv[1], NULL, 10), NULL);
		break;
	case TEST_MODE:
		test_passwords(argv[1], argv[2]);
		break;
	default:
		printf("USAGE: <program> [<n_words : int> " \
		       "| <words_file : string> <hashes_file : string>]\n");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);

	return 0;
}

void test_passwords(char *pwd_filename, char *sha_filename) {
	Hash hash;
	hash_init(&hash, sha_filename);

	FILE *fp = fopen(pwd_filename, "r");

	Word word;
	word_init(&word);

	while (!feof(fp)) {
		int len = read_line(fp, &word);
		check_hash(&word, &hash, len);
	}

	fclose(fp);

	word_free(&word);
	hash_free(&hash);
}

int read_line(FILE *fp, Word *word) {
	int c = '\0', i = 0;

	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n') {
			break;
		}

		if (i >= word->alloc) {
			word->alloc *= GROWTH_FACTOR;
			word->word = realloc(word->word, sizeof(char) * word->alloc);
			word->index = realloc(word->index, sizeof(int) * word->alloc);
			assert(word->word && word->index);
		}

		word->word[i++] = c;
	}

	return i;
}

void print_sha256(BYTE *hash) {
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
		printf("%02x", hash[i]);
	}
}

void word_init(Word *word) {
	word->word = malloc(sizeof(char) * LEN_PWD_MAX);
	word->index = malloc(sizeof(int) * LEN_PWD_MAX);
	assert(word->word && word->index);

	word->alloc = LEN_PWD_MAX;

	word_reset(word, 0, letters);
}

void word_free(Word *word) {
	free(word->word);
	free(word->index);
}

void word_reset(Word *word, int min, const char *set) {
	for (int i = min; i < LEN_PWD_MAX; i++) {
		word->index[i] = 0;
		word->word[i] = set[0];
	}
}

void hash_init(Hash *hash, char *filename) {
	FILE *fp = fopen(filename, "rb");
	assert(fp);

	// find out how long the file is
	struct stat st;
	stat(filename, &st);
	long len = st.st_size;

	hash->hashes = malloc(sizeof(BYTE) * len);
	assert(hash->hashes);
	len = fread(hash->hashes, sizeof(char), len, fp);
	fclose(fp);

	hash->count = len / SHA256_BLOCK_SIZE;

	hash->done = malloc(sizeof(int) * hash->count);
	assert(hash->done);

	memset(hash->done, 0, sizeof(int) * hash->count);
}

void hash_free(Hash *hash) {
	free(hash->hashes);
	free(hash->done);
}

void check_hash(Word *word, Hash *hash, int len) {
	BYTE word_hash[SHA256_BLOCK_SIZE];

	SHA256_CTX sha_ctx;
	sha256_init(&sha_ctx);
	sha256_update(&sha_ctx, (BYTE *) word->word, len);
	sha256_final(&sha_ctx, word_hash);

	// check the hash of word against those in hash
	for (int i = 0; i < hash->count; i++) {
		if (!hash->done[i] && !memcmp(word_hash, &hash->hashes[i * SHA256_BLOCK_SIZE], SHA256_BLOCK_SIZE)) {
			hash->done[i] = 1;

			printf("%.*s %d\n", (int) len, word->word, i + 1);
		}
	}
}


void guess_set(Word *word, int len, const char *set, int set_len, long *remaining, Hash *hash) {
	word_reset(word, len, set);
	int changed = len;

	// try the next guess from a set until we cant make any more guesses
	while ((hash || *remaining > 0) && changed >= 0) {
		if (changed < LEN_PWD_MAX) {
			make_guess(word, LEN_PWD_MAX, remaining, hash);
		}
		changed = next_set(word, len, LEN_PWD_MAX, set, set_len);
	}
}

int next_set(Word *word, int offset, int max, const char *set, int set_len) {
	// increment the part of the word after offset to be the next in the set
	for (int i = max - 1; i >= offset; i--) {
		int index = (word->index[i] + 1) % set_len;
		word->index[i] = index;
		word->word[i] = set[index];

		// index == 0 => we the next character can be incremented
		if (index != 0) {
			return i;
		}
	}

	return -1;
}

void guess_set_dict(Word *word, const char *set, long *remaining, Hash *hash) {
	FILE *fp = fopen(DICT_FILE, "r");
	assert(fp);

	// try each word in DICT_FILE with each permutaution of the set
	while (!feof(fp) && (hash || *remaining > 0)) {
		int len = read_line(fp, word);
		if (len < LEN_PWD_MAX) {
			guess_set(word, len, set, strlen(set), remaining, hash);
		}
	}
	fclose(fp);
}

void make_guess(Word *word, int len, long *remaining, Hash *hash) {
	// if we are checking against hashes
	if (hash != NULL) {
		check_hash(word, hash, len);
		return;
	}
	// else, we are just printing
	if (*remaining > 0) {
		(*remaining)--;
		printf("%.*s\n", len, word->word);
	}
}

void generate_guesses(long count, char *sha_filename) {
	int hashing = (sha_filename != NULL);

	long remaining = count;

	Word word;
	word_init(&word);

	// initialise a Hash if we are hashing, else we must be printing
	Hash hash, *hash_ptr;
	if (hashing) {
		hash_ptr = &hash;
		hash_init(hash_ptr, sha_filename);
	} else {
		hash_ptr = NULL;
	}

	// guess dictionary words
	FILE *fp = fopen(DICT_FILE, "rb");
	assert(fp);
	while (!feof(fp) && (hash_ptr || remaining > 0)) {
		int len = read_line(fp, &word);
		if (len >= LEN_PWD_MAX) {
			make_guess(&word, LEN_PWD_MAX, &remaining, hash_ptr);
		}
	}
	fclose(fp);

	guess_subs(&word, &remaining, hash_ptr);

	// guess dictionary with various character sets appended at the end
	guess_set_dict(&word, numbers, &remaining, hash_ptr);
	guess_set_dict(&word, letters, &remaining, hash_ptr);
	// guess_set_dict(&word, special, &remaining, hash_ptr);

	// resort to brute force. this could take a while if we are hashing
	if (hashing || remaining > 0) {
		// letters are a little more likely
		guess_set(&word, 0, letters, strlen(letters), &remaining, hash_ptr);
		// true brute
		guess_set(&word, 0, full, strlen(full), &remaining, hash_ptr);
	}

	// cleanup time
	if (hashing) {
		hash_free(hash_ptr);
	}
	word_free(&word);
}

void guess_subs(Word *word, long *remaining, Hash *hash) {
	FILE *fp = fopen(DICT_FILE, "r");
	assert(fp);

	// try each word in DICT_FILE with each permutaution of the set
	while (!feof(fp) && (hash || *remaining > 0)) {
		int len = read_line(fp, word);
		int count = 0;
		if (len >= LEN_PWD_MAX) {
			for (int i = 0; i < LEN_PWD_MAX; i++) {
				int c = word->word[i];
				if ('a' <= c && c <= 'z') {
					word->index[i] = c - 'a';
					count++;
				} else {
					word->index[i] = -1;
				}
			}

			if (count > 0) {
				next_sub(word, LEN_PWD_MAX, 0, 0, remaining, hash);
			}
		}
	}

	fclose(fp);
}

void next_sub(Word *word, int len, int index, int n_subs, long *remaining, Hash *hash) {
	if (index >= len || n_subs >= MAX_SUBS) {
		if (n_subs > 0) {
			make_guess(word, len, remaining, hash);
		}
		return;
	}

	next_sub(word, len, index + 1, n_subs, remaining, hash);

	int i = word->index[index];	
	if (i >= 0) {
		int sub_len = strlen(subs[i]);
		for (int s = 0; s < sub_len; s++) {
			word->word[index] = subs[i][s];
			next_sub(word, len, index + 1, n_subs + 1, remaining, hash);
		}

		word->word[index] = letters[i];
	}
}
