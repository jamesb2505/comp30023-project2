
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_IP   "172.26.37.44"
#define SERVER_PORT 7800

#define USERNAME "barnesj2"
#define G        15
#define P        97

#define BUFF_SIZE 1024

int mod_exp(int base, int exp, int mod);
void check_error(int err, char *str);
int setup(struct sockaddr_in *serv_addr);

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "USAGE: <program> <b : hex>\n");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in serv_addr;
	int sockfd = setup(&serv_addr);

	char buff[BUFF_SIZE];

	// write USERNAME to server
	int len = printf("user =\t%s\n", USERNAME);
	len = sprintf(buff, "%s\n", USERNAME);
	check_error(write(sockfd, buff, len), "write");

	// get the first byte (in decimal) from the progargs
	int b = atoi(argv[1]);
	printf("b    =\t%d\n", b);

	int g_b = mod_exp(G, b, P);
	printf("g^b  =\t%d\n", g_b);

	// write G ^ b (mod P)
	len = sprintf(buff, "%d\n", g_b);
	check_error(write(sockfd, buff, len), "write");

	// read G ^ a (mod P)
	memset(buff, 0, BUFF_SIZE);
	check_error(read(sockfd, buff, BUFF_SIZE), "read");
	int g_a = atoi(buff);
	printf("g^a  =\t%d\n", g_a);

	int g_ab = mod_exp(g_a, b, P);
	printf("g^ab =\t%d\n", g_ab);

	// write G ^ (ab) (mod P)
	len = sprintf(buff, "%d\n", g_ab);
	check_error(write(sockfd, buff, len), "write");

	// recieve message
	memset(buff, 0, BUFF_SIZE);
	len = read(sockfd, buff, BUFF_SIZE);
	check_error(len, "read");
	printf("RECIEVED: %d\n\t%s\n", len, buff);

	// all done
	close(sockfd);

	exit(EXIT_SUCCESS);
}

// calculate base ^ exp % mod
// source: Wikipedia, Modular exponentiation
// URL:    https://en.wikipedia.org/wiki/Modular_exponentiation
int mod_exp(int base, int exp, int mod) {
	if (mod == 1) {
		return 0;
	}

	int ans = 1;
	base %= mod;

	while (exp > 0) {
		if (exp & 1) {
			ans = (ans * base) % mod;
		}

		exp >>= 1;
		base = (base * base) % mod;
	}

	return ans;
}

void check_error(int err, char *str) {
	if (err < 0) {
		perror(str);
		exit(EXIT_FAILURE);
	}
}

int setup(struct sockaddr_in *serv_addr) {
	struct hostent *server;
	int sockfd;

	// buid server's data
	server = gethostbyname(SERVER_IP);
	if (!server) {
		fprintf(stderr, "ERROR, no such host\n");
		exit(EXIT_FAILURE);
	}

	bzero((char *) serv_addr, sizeof(serv_addr));
	serv_addr->sin_family = AF_INET;
	bcopy((char *) server->h_addr_list[0], (char *) &serv_addr->sin_addr.s_addr,
	      server->h_length);
	serv_addr->sin_port = htons(SERVER_PORT);

	// initialise a socket
	check_error((sockfd = socket(PF_INET, SOCK_STREAM, 0)), "socket");

	// connect to server
	check_error(connect(sockfd, (struct sockaddr *) serv_addr,
	                    sizeof(*serv_addr)),
	            "connect");

	return sockfd;
}