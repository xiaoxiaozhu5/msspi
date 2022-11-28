// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
//#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "../src/msspi.h"

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

int main()
{
	const char server_name[] = "www.google.com";

	int rc = 0;
	SOCKET s = INVALID_SOCKET;
	struct sockaddr_in* addr = nullptr;
	struct addrinfo* result = nullptr;
	struct addrinfo* ptr = nullptr;
	struct addrinfo hints;

	MSSPI_HANDLE hMsspi = nullptr;
	do
	{
		WSADATA wsa{};
		WSAStartup(MAKEWORD(2,2), &wsa);

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

		addr->sin_port = htons(443);
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
		if(rc <= 0)
		{
			std::cout << "msspi: send GET failed\n";
			break;
		}

		bool chunked = false;
		again:
		const int tmp_len = 16 * 1024;
		char *tmp = new char[tmp_len];
		ZeroMemory(tmp, tmp_len);
		rc = SSL_get_error_msspi(hMsspi, msspi_read(hMsspi, tmp, tmp_len));
		if(rc == SSL_ERROR_NONE)
		{
			std::cout << tmp;

			if(strstr(tmp, "Transfer-Encoding: chunked"))
			{
				chunked = true;
			}
			if(chunked)
			{
				goto again;
			}
		}
		else
		{
			std::cout << "msspi: get response failed:" << rc << std::endl;
		}

	} while (false);

	if (result)
	{
		freeaddrinfo(result);
	}
	if(hMsspi)
	{
		msspi_shutdown(hMsspi);
		msspi_close(hMsspi);
		hMsspi = nullptr;
	}
	if(s != INVALID_SOCKET)
	{
		shutdown(s, SD_BOTH);
		closesocket(s);
		s = INVALID_SOCKET;
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
