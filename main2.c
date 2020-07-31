#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include "sha256.h"

#define PWD4SHA256  "pwd4sha256"
#define PWD6SHA256  "pwd6sha256"
#define PWD46SHA256 "pwd46sha256"

#define DICT_FILE "common_words.txt"

#define GENERATE_MODE 1
#define GUESS_MODE    2
#define TEST_MODE     3

#define MIN_PWD_LEN    4
#define MAX_PWD_LEN    6
#define MIN_PWD_CHAR  32
#define MAX_PWD_CHAR 126

#define NEXT_CHAR(C) (((((C) - MIN_PWD_CHAR + 1) % \
(MAX_PWD_CHAR - MIN_PWD_CHAR + 1)) + MIN_PWD_CHAR))
#define CARRIED_CHAR(C) ((C) == MIN_PWD_CHAR)

typedef struct {
	BYTE *hashes;
	char *done;
	long count, correct;
} Hash;

typedef struct {
	int index[MAX_PWD_LEN];
	char word[MAX_PWD_LEN];
	int subs[MAX_PWD_LEN];
} Word;

void generate_words(long n);
void test_passwords(char *pwd_filename, char *sha_filename);
BYTE *load_sha256file(char *filename, long *len);
int read_line(FILE *fp, char *str);

void print_sha256(BYTE *hash);

void word_init(Word *word);
int word_next(Word *word);
void word_caps(Word *word, Hash *hash);
int word_next_cap(Word *word);

void hash_init(Hash *hash, char *filename);
void hash_free(Hash *hash);

int check_hash(Word *word, Hash *hash, long len);

long check_caps(Word *word, Hash *hashes);

// order based on English letter frequencies
static const char *letters = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

// 0  3   7  11  15  19  23
static const int letters_len = 97;

// based on common substitiutions (e.g. 1337)
static const char *subs[] = {
	"ETAOINSRHDLUCMFYWGPBVKXQJZ",
	"37401 5 #]7 ( =  6 8   9 2",
	" +@ ! $  )  [             ",
	"    |    }  {             ",
	"         >  <             "
};
static const int subs_len = 5;

//static const char cap_offset = 'A' - 'a';


FILE *f;

int main(int argc, char *argv[]) {
	Word word, init;
	word_init(&word);
	word_init(&init);

	// memset(word.word, ' ', MAX_PWD_LEN);
	// memset(init.word, ' ', MAX_PWD_LEN);
	strncpy(word.word, argv[1], MAX_PWD_LEN);
	for (int i = 0; i < letters_len; i++) {
		for (int j = 0; j < MAX_PWD_LEN; j++) {
			if (word.word[j] == letters[i]) {
				word.index[j] = i;
			}
		}
	}

	Hash hash;
	hash_init(&hash, PWD46SHA256);

	for (long i = 0; ; i++) {
		check_hash(&word, &hash, MAX_PWD_LEN);

		if (i % 50000000 == 0) {
			printf("%.6s\n", word.word);
		}
		if (word.word[0] == argv[1][0] + 10) {
			printf("done\n");
			break;

		}

		if (word_next(&word) < 0) {
			break;
		}
	}

	hash_free(&hash);

	exit(EXIT_SUCCESS);
}


void generate_words(long n) {
	//int len = MAX_PWD_LEN;
	Word word, init;
	word_init(&word);
	word_init(&init);

	// memset(word.word, ' ', MAX_PWD_LEN);
	// memset(init.word, ' ', MAX_PWD_LEN);
	strncpy(word.word, "eeeeee", MAX_PWD_LEN); 
	for (int i = 0; i < letters_len; i++) {
		for (int j = 0; j < MAX_PWD_LEN; j++) {
			if (word.word[j] == letters[i]) {
				word.index[j] = i;
			}
		}
	}

	Hash hash;
	hash_init(&hash, PWD46SHA256);

	for (long i = 0; n <= 0 || i < n; i++) {
		check_hash(&word, &hash, MAX_PWD_LEN);
		// check_hash(&word, &hash, MIN_PWD_LEN);

		if (i % 500000 == 0) {
			printf("%.6s\n", word.word);
		}
		// if (check_hash(&word, &hash, MAX_PWD_LEN)) {
		// word_caps(&word, &hash);
		// }
		if (word_next(&word) < 0) {
			break;
		}

		// if (word_next(&word) <= MIN_PWD_LEN) {
		// 	check_hash(&word, &hash, MIN_PWD_LEN);
		// }
		// for (int j = 0; j < MAX_PWD_LEN; j++) {
		// 	word.word[j] = NEXT_CHAR(word.word[j]);
		// 	if (!CARRIED_CHAR(word.word[j])) {
		// 		break;
		// 	}
		// }

		// if (!strncmp(init.word, word.word, len)) {
		// 	break;
		// }
	}

	hash_free(&hash);
}

BYTE *load_sha256file(char *filename, long *len) {
	FILE *fp = fopen(filename, "rb");
	assert(fp);

	struct stat st;
	stat(filename, &st);
	*len = st.st_size;

	BYTE *contents = malloc(*len + 1);
	assert(contents);

	long l = fread(contents, sizeof(char), *len, fp);
	contents[l] = '\0';

	fclose(fp);

	return contents;
}

int read_line(FILE *fp, char *str) {
	int c = '\0', i = 0;

	while ((c = fgetc(fp)) != EOF) {
		if (c < MIN_PWD_CHAR || c > MAX_PWD_CHAR) {
			break;
		}

		str[i++] = c;
	}

	str[i] = '\0';

	return i;
}

void print_sha256(BYTE *hash) {
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
		printf("%02x", hash[i]);
	}
}

void word_init(Word *word) {
	for (int i = 0; i < MAX_PWD_LEN; i++) {
		word->word[i] = letters[0];
		word->index[i] = 0;
		word->subs[i] = 0;
	}
}

int word_next(Word *word) {
	for (long i = MAX_PWD_LEN - 1; i >= 0; i--) {
		int index = word->index[i] = (word->index[i] + 1) % letters_len;
		word->word[i] = letters[index];

		if (index != 0) {
			return i;
		}
	}

	return -1;
}

void word_caps(Word *word, Hash *hash) {
	char lower[MAX_PWD_LEN];
	memcpy(lower, word->word, MAX_PWD_LEN);

	do {
		check_hash(word, hash, MAX_PWD_LEN);
		// printf("  %.*s\n", MAX_PWD_LEN, word->word);
		if (word_next_cap(word) < 0) {
			break;
		}
		// if (word_next_cap(word) <= MIN_PWD_LEN) {
		// check_hash(word, hash, MIN_PWD_LEN);
		// }
	} while (1);// strncmp(lower, word->word, MAX_PWD_LEN));
}

int word_next_cap(Word *word) {
	for (long i = MAX_PWD_LEN - 1; i >= 0; i--) {
		char c = word->word[i];
		int index = word->index[i];
		if (c == letters[index]) {
			word->word[i] = subs[0][index];
			return i;
		}
		int s = word->subs[i];
		if (s < subs_len - 1 && subs[s + 1][index] != ' ') {
			word->subs[i]++;
			word->word[i] = subs[s + 1][index];
			return i;
		} else {
			word->subs[i] = 0;
			word->word[i] = letters[index];
		}
	}

	return -1;
}

void hash_init(Hash *hash, char *filename) {
	FILE *fp = fopen(filename, "rb");
	assert(fp);

	struct stat st;
	stat(filename, &st);
	long len = st.st_size;

	hash->hashes = malloc(sizeof(BYTE) * (len + 1));
	assert(hash->hashes);

	len = fread(hash->hashes, sizeof(char), len, fp);
	hash->hashes[len] = '\0';

	fclose(fp);

	hash->count = len / SHA256_BLOCK_SIZE;

	hash->done = malloc(sizeof(char) * hash->count);
	assert(hash->done);
	memset(hash->done, 0, sizeof(char) * hash->count);
	hash->done[0] = 1; hash->done[1] = 1; hash->done[2] = 1;
	hash->done[3] = 1; hash->done[4] = 1; hash->done[5] = 1;
	hash->done[6] = 1; hash->done[7] = 1; hash->done[8] = 1;
	hash->done[9] = 1; hash->done[11] = 1; hash->done[12] = 1;
	hash->done[13] = 1; hash->done[14] = 1; hash->done[16] = 1;
	hash->done[17] = 1; hash->done[18] = 1; hash->done[18] = 1;
	hash->done[19] = 1; hash->done[20] = 1; hash->done[21] = 1;
	hash->done[22] = 1; hash->done[23] = 1; hash->done[24] = 1;
	hash->done[25] = 1; hash->done[26] = 1; hash->done[29] = 1;

	hash->correct = 25;
}

void hash_free(Hash *hash) {
	free(hash->hashes);
	free(hash->done);
}

int check_hash(Word *word, Hash *hash, long len) {
	BYTE word_hash[SHA256_BLOCK_SIZE];

	SHA256_CTX sha_ctx;
	sha256_init(&sha_ctx);
	sha256_update(&sha_ctx, (BYTE *) word->word, len);
	sha256_final(&sha_ctx, word_hash);

	for (long i = 10; i < hash->count; i++) {
		if (!hash->done[i] && !memcmp(word_hash, &hash->hashes[i * SHA256_BLOCK_SIZE], SHA256_BLOCK_SIZE)) {
			hash->done[i] = 1;
			hash->correct++;

			printf("%.*s %ld\n", (int) len, word->word, i);
			f = fopen("out.txt", "a+");
			fprintf(f, "%.*s %ld\n", (int) len, word->word, i);
			fclose(f);
			return 1;
		}
	}

	return 0;
}