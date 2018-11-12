#include <stdio.h>
#include <iostream>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#define MAX_PACKETLEN 1460
using namespace std;

int main(int argc, char* argv[])
{
	char ReadBuffer[MAX_PACKETLEN] = { "\n" }, WriteBuffer[MAX_PACKETLEN] = "HTTP/1.1 200 OK\nContent-Length:5\n\nhello\0";
	int Readn, Writen;
	if (argc != 2) {
		cout << "ex) " << argv[0] << "<Port>" << endl;
		return -1;
	}

	WSADATA WsaData;


	// initalization
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		cout << "Socket reset error" << endl;
	}

	SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
	if (server == SOCKET_ERROR) {
		cout << "Socket create error" << endl;
		WSACleanup();
	}

	sockaddr_in server_addr, client_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[1]));
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);



	if (bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
	{	
		cout << "bind error" << endl;
	}
	if (listen(server, 5) == SOCKET_ERROR)
	{
		cout << "listen error" << endl;
	}

	SSL_library_init();				
	SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_server_method());
	SSL_CTX_use_certificate_file(ctx, "C:\\Program Files\\SnoopSpy\\certificate\\test.com.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "C:\\Program Files\\SnoopSpy\\certificate\\test.com.key", SSL_FILETYPE_PEM);
	while (1)
	{
		cout << "1. hi" << endl;
		int client_addr_size = sizeof(client_addr);
		SOCKET client = accept(server, (struct sockaddr *)&client_addr, &client_addr_size);
		cout << "3. hi" << endl;
		if (client == SOCKET_ERROR) {
			cout << "accept error" << endl;
			return -1;
		} 
		cout << "2. hi" << endl;
		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		SSL_accept(ssl);
		
		while (SSL_read(ssl, ReadBuffer, sizeof(ReadBuffer)) > 0) {
			cout << ReadBuffer << endl;
			memset(ReadBuffer, '\0', sizeof(ReadBuffer));
			SSL_write(ssl, WriteBuffer, strlen(WriteBuffer));
			SSL_free(ssl);
		}
	}
	SSL_CTX_free(ctx);
	WSACleanup();
	closesocket(server);
}
