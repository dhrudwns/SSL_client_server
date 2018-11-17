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
	SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // IPv4, TCP, TCP
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
	{
		cout << "bind error : " << WSAGetLastError() << endl;
	}
	if (listen(server_socket, 5) == SOCKET_ERROR) // (bind complet socket, backlog)
	{
		cout << "listen error : " << WSAGetLastError() << endl;
	}

	return server_socket;
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms(); // initalization ssl
}

void cleanup_openssl()
{
	EVP_cleanup(); 
}

SSL_CTX *create_context()
{
	SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_server_method()); //TLSv1.2 context create
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	// crt load to ctx, success return 1
	if (SSL_CTX_use_certificate_file(ctx, "C:\\Program Files\\SnoopSpy\\certificate\\test.com.pem", SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	// pkey add to ctx
	if (SSL_CTX_use_PrivateKey_file(ctx, "C:\\Program Files\\SnoopSpy\\certificate\\test.com.key", SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}
int main(int argc, char* argv[])
{
	SSL_CTX *ctx;
	struct sockaddr_in client_addr;
	int client_addr_size = sizeof(client_addr);
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Socket reset error : " << WSAGetLastError() << endl;
	}

	init_openssl();
	ctx = create_context();
	configure_context(ctx);

	SOCKET socket = create_socket(atoi(argv[1]));

	while (1) {
		SSL *ssl;
		char *server_hello = "HTTP/1.1 200 OK\nContent-Length: 5\n\nHello\n\0", c_message[MAX_PACKETLEN] = { "\0", };
		
		SOCKET client_socket = accept(socket, (struct sockaddr *)&client_addr, &client_addr_size);
		if (client_socket == SOCKET_ERROR) {
			cout << "accept error : " << WSAGetLastError() << endl;
		}
		ssl = SSL_new(ctx); // create ssl structs
		SSL_set_fd(ssl, client_socket); // connect ssl with client, SOCKET BIO auto create

		// handshake, success return 1
		if (SSL_accept(ssl) <= 0) {
			cout << "ssl accept error : ";
			ERR_print_errors_fp(stderr);
			
		}
		else {
			SSL_read(ssl, c_message, sizeof(c_message));
			cout << c_message;
			SSL_write(ssl, server_hello, strlen(server_hello));
		}

		SSL_free(ssl); // ssl struct cancel
		closesocket(client_socket);
	}
	closesocket(socket);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	WSACleanup();
}
