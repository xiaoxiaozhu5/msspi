// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
//#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "../src/msspi.h"

#pragma warning(disable: 4996)

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

#define SSL_ERROR_NONE          0
#define SSL_ERROR_SSL           1
#define SSL_ERROR_WANT_READ     2
#define SSL_ERROR_WANT_WRITE        3
#define SSL_ERROR_WANT_X509_LOOKUP  4
#define SSL_ERROR_SYSCALL       5 /* look at error stack/return value/errno */
#define SSL_ERROR_ZERO_RETURN       6

int my_read_cb(void* cb_arg, void* buf, int len);
int my_write_cb(void* cb_arg, const void* buf, int len);

int SSL_get_error_msspi(MSSPI_HANDLE h, int ret);
std::string read_file_to_buffer(const char* file);

void get_app_path(std::string& sPath)
{
	char szTem[MAX_PATH] = {0};
	GetModuleFileNameA(NULL, szTem, sizeof(szTem));
	strrchr(szTem, '\\')[1] = '\0';
	sPath = szTem;
}

void client_test(char* server_address)
{
	char* server_name = nullptr;
	uint16_t port = 443;
	auto port_ptr = strchr(server_address, ':');
	if (port_ptr != nullptr)
	{
		port = atoi(port_ptr + 1);
		*port_ptr = '\0';
		server_name = server_address;
	}
	else
	{
		server_name = server_address;
	}

	int rc = 0;
	SOCKET s = INVALID_SOCKET;
	struct sockaddr_in* addr = nullptr;
	struct addrinfo* result = nullptr;
	struct addrinfo* ptr = nullptr;
	struct addrinfo hints;

	MSSPI_HANDLE hMsspi = nullptr;
	do
	{
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET)
		{
			std::cout << "socket: create failed:" << WSAGetLastError() << std::endl;
			break;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;
		rc = getaddrinfo(server_name, nullptr, &hints, &result);
		if (rc != 0)
		{
			std::cout << "socket: get address failed:" << rc << std::endl;
			break;
		}

		for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
		{
			addr = (struct sockaddr_in*)ptr->ai_addr;
			break;
		}

		addr->sin_port = htons(port);
		int name_len = sizeof(struct sockaddr_in);
		rc = ::connect(s, (const sockaddr*)addr, name_len);
		if (rc == SOCKET_ERROR)
		{
			std::cout << "socket: connect failed:" << WSAGetLastError() << std::endl;
			break;
		}

		hMsspi = msspi_open(&s, my_read_cb, my_write_cb);
		if (hMsspi == nullptr)
		{
			std::cout << "msspi: open failed\n";
			break;
		}
		msspi_set_version(hMsspi, TLS1_1_VERSION, TLS1_3_VERSION);
		msspi_set_hostname(hMsspi, server_name);
		msspi_set_client(hMsspi);

		while (true)
		{
			rc = SSL_get_error_msspi(hMsspi, msspi_connect(hMsspi));
			if (rc == SSL_ERROR_NONE)
			{
				break;
			}
			if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
			{
				fd_set read_set, write_set;
				FD_ZERO(&read_set);
				FD_ZERO(&write_set);

				if (rc == SSL_ERROR_WANT_READ)
					FD_SET(s, &read_set);
				if (rc == SSL_ERROR_WANT_WRITE)
					FD_SET(s, &write_set);

				struct timeval tv{};
				tv.tv_sec = 0;
				tv.tv_usec = 3000;
				int r = select(s + 1, &read_set, &write_set, nullptr, &tv);
				if (r < 0)
				{
					std::cout << "socket: select fail:" << WSAGetLastError() << std::endl;
					rc = r;
					break;
				}
				if (r == 0)
				{
					std::cout << "socket: select shutdown\n";
					rc = r;
					break;
				}
				if (rc == SSL_ERROR_WANT_READ)
				{
					if (FD_ISSET(s, &read_set))
					{
						rc = 0;
						break;
					}
				}
				if (rc == SSL_ERROR_WANT_WRITE)
				{
					if (FD_ISSET(s, &write_set))
					{
						rc = 0;
						break;
					}
				}
			}
			if (rc == SSL_ERROR_SYSCALL)
			{
				DWORD dwRet = WSAGetLastError();
				if (dwRet == WSAEINTR || dwRet == WSAEWOULDBLOCK)
				{
					continue;
				}
				break;
			}
		}
		if (rc != 0)
		{
			std::cout << "msspi: connect failed\n";
			break;
		}

		const char* get_header = "GET / HTTP/1.1\r\n"
			"Host: www.google.com\r\n"
			"user-agent: msspi/1.0.0\r\n"
			"accept: */*\r\n\r\n";

		rc = msspi_write(hMsspi, get_header, strlen(get_header));
		if (rc <= 0)
		{
			std::cout << "msspi: send GET failed\n";
			break;
		}

		bool chunked = false;
	again:
		const int tmp_len = 16 * 1024;
		char* tmp = new char[tmp_len];
		ZeroMemory(tmp, tmp_len);
		rc = SSL_get_error_msspi(hMsspi, msspi_read(hMsspi, tmp, tmp_len));
		if (rc == SSL_ERROR_NONE)
		{
			if (strstr(tmp, "Transfer-Encoding: chunked"))
			{
				chunked = true;
			}
			std::cout << tmp;
			delete[] tmp;
			if (chunked)
			{
				goto again;
			}
		}
		else
		{
			std::cout << "msspi: get response failed:" << rc << std::endl;
			delete[] tmp;
		}
	} while (false);

	if (result)
	{
		freeaddrinfo(result);
	}
	if (hMsspi)
	{
		msspi_shutdown(hMsspi);
		msspi_close(hMsspi);
		hMsspi = nullptr;
	}
	if (s != INVALID_SOCKET)
	{
		shutdown(s, SD_BOTH);
		closesocket(s);
		s = INVALID_SOCKET;
	}
}

void server_test(uint16_t port)
{
	SOCKET s = INVALID_SOCKET;
	MSSPI_HANDLE hMsspiHandle = nullptr;
	int rc = 0;
	do
	{
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET)
		{
			std::cout << "socket: create socket failed:" << WSAGetLastError() << std::endl;
			break;
		}

		struct sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = ADDR_ANY;
		int name_len = sizeof(addr);
		rc = bind(s, (const struct sockaddr*)&addr, name_len);
		if (rc == SOCKET_ERROR)
		{
			std::cout << "socket: bind socket failed:" << WSAGetLastError() << std::endl;
			break;
		}

		rc = listen(s, SOMAXCONN);
		if (rc == SOCKET_ERROR)
		{
			std::cout << "socket: listen socket failed:" << WSAGetLastError() << std::endl;
			break;
		}


		struct sockaddr_in client_addr{};
		int client_addr_len = sizeof(client_addr);
		SOCKET client = accept(s, (struct sockaddr*)&client_addr, &client_addr_len);
		if (client == INVALID_SOCKET)
		{
			std::cout << "socket: accept failed:" << WSAGetLastError() << std::endl;
			break;
		}

		hMsspiHandle = msspi_open(&client, my_read_cb, my_write_cb);
		if (hMsspiHandle == nullptr)
		{
			std::cout << "msspi: open failed\n";
			break;
		}

		msspi_set_version(hMsspiHandle, TLS1_1_VERSION, TLS1_3_VERSION);

		//NOTE: generate self-signed certificate
		//makecert.exe -r -pe -n "cn=MyCA" -$ commercial -a sha1 -b 08/05/2022 -e 01/01/2032 -cy authority -ss my -sr currentuser
		//export from MMC without private key in base64 encoded X.509 CER file
		std::string cert_path;
		get_app_path(cert_path);
		cert_path += "ca-cert.cer";
		auto cert_file = read_file_to_buffer(cert_path.c_str());
		if(cert_file.empty())
		{
			std::cout << "msspi: no ca-cert.cer found\n";
			break;
		}
		if(!msspi_add_mycert(hMsspiHandle, cert_file.c_str(), cert_file.size()))
		{
			std::cout << "msspi: add ca-cert.cer failed\n";
			break;
		}

		while (true)
		{
			rc = SSL_get_error_msspi(hMsspiHandle, msspi_accept(hMsspiHandle));
			if (rc == SSL_ERROR_NONE)
			{
				break;
			}
			if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
			{
				fd_set read_set, write_set;
				FD_ZERO(&read_set);
				FD_ZERO(&write_set);

				if (rc == SSL_ERROR_WANT_READ)
					FD_SET(client, &read_set);
				if (rc == SSL_ERROR_WANT_WRITE)
					FD_SET(client, &write_set);

				struct timeval tv{};
				tv.tv_sec = 0;
				tv.tv_usec = 3000;
				int r = select(client + 1, &read_set, &write_set, nullptr, &tv);
				if (r < 0)
				{
					std::cout << "socket: select fail:" << WSAGetLastError() << std::endl;
					rc = r;
					break;
				}
				if (r == 0)
				{
					std::cout << "socket: select shutdown\n";
					rc = r;
					break;
				}
				if (rc == SSL_ERROR_WANT_READ)
				{
					if (FD_ISSET(client, &read_set))
					{
						rc = 0;
						break;
					}
				}
				if (rc == SSL_ERROR_WANT_WRITE)
				{
					if (FD_ISSET(client, &write_set))
					{
						rc = 0;
						break;
					}
				}
			}
			if (rc == SSL_ERROR_SYSCALL)
			{
				DWORD dwRet = WSAGetLastError();
				if (dwRet == WSAEINTR || dwRet == WSAEWOULDBLOCK)
				{
					continue;
				}
				std::cout << "msspi: accept failed:" << dwRet << std::endl;
				break;
			}
		}
		if (rc != SSL_ERROR_NONE)
		{
			std::cout << "msspi: accept failed\n";
			break;
		}

		const int tmp_len = 16 * 1024;
		char* tmp = new char[tmp_len];
		ZeroMemory(tmp, tmp_len);
		rc = SSL_get_error_msspi(hMsspiHandle, msspi_read(hMsspiHandle, tmp, tmp_len));
		if (rc != SSL_ERROR_NONE)
		{
			std::cout << "msspi: read failed\n";
			delete[] tmp;
			break;
		}

		std::cout << tmp;
		ZeroMemory(tmp, tmp_len);
		snprintf(tmp, tmp_len, "%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n\r\n%s\r\n", "HTTP/1.1 200 OK",
		         "Date: Tue, 29 Nov 2022 06:40:28 GMT", "Cache-Control: no-cache", "Content-Length: 17",
		         "Content-Type: text/plain", "hello from server");
		rc = SSL_get_error_msspi(hMsspiHandle, msspi_write(hMsspiHandle, tmp, tmp_len));
		if (rc != SSL_ERROR_NONE)
		{
			std::cout << "msspi: write failed\n";
			delete[] tmp;
			break;
		}
		delete[] tmp;

		shutdown(client, SD_BOTH);
		closesocket(client);
		client = INVALID_SOCKET;
	} while (false);

	if (hMsspiHandle)
	{
		msspi_close(hMsspiHandle);
		hMsspiHandle = nullptr;
	}

	if (s != INVALID_SOCKET)
	{
		shutdown(s, SD_BOTH);
		closesocket(s);
		s = INVALID_SOCKET;
	}
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		std::cout << argv[0] << " client|server server address|listen port\n";
		std::cout << "example: " << argv[0] << " client www.google.com:443 or client www.google.com\n";
		std::cout << "example: " << argv[0] << " server 7749\n";
		return -1;
	}

	WSADATA wsa{};
	WSAStartup(MAKEWORD(2, 2), &wsa);

	if (strcmp(argv[1], "client") == 0)
	{
		client_test(argv[2]);
	}
	else if (strcmp(argv[1], "server") == 0)
	{
		server_test(atoi(argv[2]));
	}

	WSACleanup();
	return 0;
}

int my_read_cb(void* cb_arg, void* buf, int len)
{
	int rc = ::recv(*(SOCKET*)cb_arg, (char*)buf, len, 0);
	return rc;
}

int my_write_cb(void* cb_arg, const void* buf, int len)
{
	int rc = ::send(*(SOCKET*)cb_arg, (const char*)buf, len, 0);
	return rc;
}

int SSL_get_error_msspi(MSSPI_HANDLE h, int ret)
{
	int err;
	if (ret > 0)
		return SSL_ERROR_NONE;
	err = msspi_state(h);
	if (err & MSSPI_ERROR)
		return SSL_ERROR_SYSCALL;
	if (err & (MSSPI_SENT_SHUTDOWN | MSSPI_RECEIVED_SHUTDOWN))
		return SSL_ERROR_ZERO_RETURN;
	if (err & MSSPI_WRITING)
	{
		if (err & MSSPI_LAST_PROC_WRITE)
			return SSL_ERROR_WANT_WRITE;
		if (err & MSSPI_READING)
			return SSL_ERROR_WANT_READ;
		return SSL_ERROR_WANT_WRITE;
	}
	if (err & MSSPI_READING)
		return SSL_ERROR_WANT_READ;
	return SSL_ERROR_NONE;
}

std::string read_file_to_buffer(const char* file)
{
	FILE* cert_file = NULL;
	char *str_file = NULL;
	long size_file;

	std::string buffer;
	do
	{
		if ((cert_file = fopen(file, "rb")) == NULL)
		{
			break;
		}
		if (fseek(cert_file, 0, SEEK_END) == -1L)
		{
			break;
		}
		if ((size_file = ftell(cert_file)) > 1024 * 1024)
		{
			break;
		}
		if ((fseek(cert_file, 0, 0)) == -1L)
		{
			break;
		}
		buffer.resize(size_file);
		if ((str_file = (char*)malloc(sizeof(char) * (size_t)size_file)) == NULL)
		{
			break;
		}
		if (fread(str_file, sizeof(char), (size_t)size_file, cert_file) != (unsigned long int)size_file)
		{
			break;
		}
		buffer.assign(str_file, size_file);
	} while (false);
	free(str_file);
	if(cert_file)
	{
		fclose(cert_file);
	}
	return buffer;
}
