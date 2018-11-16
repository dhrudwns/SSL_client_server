#include <stdio.h>
#include <iostream>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#define MAX_PACKETLEN 1460
using namespace std;

int create_socket(int port)
{
	SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	return server_socket;
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms(); // initalizaiton ssl
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_server_method());
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void printCert(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);							/* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);							/* free the malloc'ed string */
		X509_free(cert);					/* free the malloc'ed certificate copy */
	}
	else
		printf("No certificates.\n");
}
int main(int argc, char* argv[])
{
	SSL_CTX *ctx;
	SSL *ssl;
	char buf[1024];
	int bytes;
	sockaddr_in client_addr;
	int client_addr_size = sizeof(client_addr);
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Socket reset error : " << WSAGetLastError() << endl;
	}

	init_openssl();
	ctx = create_context();
	SOCKET server = create_socket(atoi(argv[1]));
	ssl = SSL_new(ctx);						/* create new SSL connection state */
	SSL_set_fd(ssl, server);				/* attach the socket descriptor */
	
	if (SSL_connect(ssl) == -1)			/* perform the connection */
		ERR_print_errors_fp(stderr);
	else
	{
		char *msg = "Hello???";

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		printCert(ssl);								/* get any certs */
		SSL_write(ssl, msg, strlen(msg));			/* encrypt & send message */
		bytes = SSL_read(ssl, buf, sizeof(buf));	/* get reply & decrypt */
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);
	}
	
	SSL_free(ssl);								/* release connection state */
	closesocket(server);									/* close socket */
	SSL_CTX_free(ctx);								/* release context */
	cleanup_openssl();
	WSACleanup();
}
