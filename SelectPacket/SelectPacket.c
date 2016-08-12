/*
* webfilter.c
* (C) 2013, all rights reserved,
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
* DESCRIPTION:
* This is a simple web (HTTP) filter using WinDivert.
*
* It works by intercepting outbound HTTP GET/POST requests and matching
* the URL against a blacklist.  If the URL is matched, we hijack the TCP
* connection, reseting the connection at the server end, and sending a
* blockpage to the browser.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "windivert.h"

#define MAXBUF 0xFFFF
#define MAXURL 4096

/*
* URL�� ������Ʈ ����ü�Դϴ�.
*/
typedef struct
{
	char *domain;
	char *uri;
} URL, *PURL;
typedef struct
{
	UINT size;
	UINT length;
	PURL *urls;
} BLACKLIST, *PBLACKLIST;

/*
* ��Ŷ�� �̸� �����մϴ�.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;
typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

/*
* Blockpage�� ������ �������� �̸� ����ϴ�.
*/
const char block_data[] =
"HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<!doctype html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>BLOCKED!</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<h1>BLOCKED!</h1>\n"
"\t\t<hr>\n"
"\t\t<p>This URL has been blocked!</p>\n"
"\t</body>\n"
"</html>\n";

char* timeToString(struct tm *t);
void PacketInit(PPACKET packet);
int __cdecl UrlCompare(const void *a, const void *b);
int UrlMatch(PURL urla, PURL urlb);
PBLACKLIST BlackListInit(void);
void BlackListInsert(PBLACKLIST blacklist, PURL url);
void BlackListSort(PBLACKLIST blacklist);
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);
void BlackListRead(PBLACKLIST blacklist, const char *filename);
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data,
	UINT16 len);

/*
 Packet�� �ڸ��� ������ ���� main�Լ�
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	PACKET finish0;
	PPACKET finish = &finish0;
	PDATAPACKET blockpage;
	UINT16 blockpage_len;
	PBLACKLIST blacklist;

	INT16 priority = 404;       // Arbitrary.



	//������Ʈ �ʱ�ȭ �մϴ�.
	blacklist = BlackListInit();

	//BlackList�� �о�ɴϴ�.
	BlackListRead(blacklist, "mal_site.txt");
	
	//BlackList�� �����մϴ�.
	BlackListSort(blacklist);
	
	//�̸� ������� ��Ŷ�� �ʱ�ȭ�մϴ�.
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);
	if (blockpage == NULL)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	//PacketInit�� ���� ��Ŷ���� �ʱ�ȭ�մϴ�.
	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);				//blockpage�� ����� ip���������� ���̸� ��Ʈ��ũ ���Ŀ� �°� �����Ѵ�.
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;									//�����͸� �������� 7�������� �ٷ� �����մϴ�.
	blockpage->header.tcp.Ack = 1;									
	
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);	//blockpage�� �����Ϳ� block_data�� ����ֽ��ϴ�.
	
	//PacketInit�� reset(�缳��)���� �ʱ�ȭ�մϴ�.
	PacketInit(reset);												
	reset->tcp.Rst = 1;												//�缳���̴�. �� ���⿡�� ���ÿ� �Ͼ�� ���������� ���� �����Դϴ�.
	reset->tcp.Ack = 1;												//������� Sequence Number�� TCP�� ���� �Ǵ� ������ ���� ���� �Ͱ� ���� ACK ������ �ݴϴ�.
	
	//PacketInit�� ������ �����ֵ��� �ʱ�ȭ�մϴ�.
	PacketInit(finish);												//Packet�� �ʱ�ȭ �� �ݴϴ�.
	finish->tcp.Fin = 1;											//������ ���� ��û�̴�. �������� ���Ḧ �ǹ��մϴ�.
	finish->tcp.Ack = 1;											//������� Sequence Number�� TCP�� ���� �Ǵ� ������ ���� ���� �Ͱ� ���� ACK ������ �ݴϴ�.

	// Divert device�� ���ǿ� ���� ����
	handle = WinDivertOpen(
		"outbound && "              // ������ ���� ����ϴ�.
		"ip && "                    // IPv4�� ���ݴϴ�.
		"tcp.DstPort == 80 && "     // HTTP�� ��´ٴ� �ǹ��Դϴ�. (��Ʈ 80)
		"tcp.PayloadLength > 0",    // TCP�������� ���̰� 0 �̻��� �͸� ��´ٴ� �ǹ��Դϴ�.
		WINDIVERT_LAYER_NETWORK,    // ��Ʈ��ũ �������� ����ϴ�.
		priority,					//�켱������ 404(����)�Դϴ�.
		0 //�÷��״� 0���� �����Ͽ� �ݴϴ�.
	);
	
	//�ڵ鰪�� ��ȯ�Ǿ����� Ȯ���մϴ�.
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	//�ڵ鰪�� ���������� ��ȯ�Ǿ����� �ǹ��մϴ�.
	printf("OPENED WinDivert\n");

	// ���� ������ �����մϴ�.
	while (TRUE)
	{
		//��Ŷ�� �����Ѵ�.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		//WinDivert Helper ���� �м��մϴ�.
		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char *)payload, (UINT16)payload_len))
		{
			// packat�� URL���� ������Ʈ�� ��ġ���� ���� �� ������ �� ���� ���ݴϴ�.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// URL�� ������Ʈ�� ��ġ�Ѵٸ� TCP�� �����մϴ�.

		// (1) ������ TCP RST�� �����־� ������ �����ִ� �κ��Դϴ�.
		reset->ip.SrcAddr = ip_header->SrcAddr;
		reset->ip.DstAddr = ip_header->DstAddr;
		reset->tcp.SrcPort = tcp_header->SrcPort;
		reset->tcp.DstPort = htons(80);
		reset->tcp.SeqNum = tcp_header->SeqNum;
		reset->tcp.AckNum = tcp_header->AckNum;
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) �������� blockpage�� �����ִ� �κ��Դϴ�.
		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;    
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))// ���Ե� �� ����Ʈ ��, �ʿ����� ���� ��쿡�� NULL�� �־��� �� �ֽ��ϴ�.
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) �������� TCP FIN �÷��׸� �����־� ������ �ݾ��ִ� �κ��Դϴ�.
		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data) - 1);
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}
	}
}

/*
* ��Ŷ�� �ʱ�ȭ�մϴ�.
*/
void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* ������Ʈ�� �ʱ�ȭ�մϴ�.
*/
PBLACKLIST BlackListInit(void)
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));
	UINT size;
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;
	blacklist->urls = (PURL *)malloc(size * sizeof(PURL));
	if (blacklist->urls == NULL)
	{
		goto memory_error;
	}
	blacklist->size = size;
	blacklist->length = 0;

	return blacklist;

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}

/*
* ������Ʈ�� url�� ����ֽ��ϴ�.
*/
void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)
	{
		blacklist->size = (blacklist->size * 3) / 2;
		printf("GROW blacklist to %u\n", blacklist->size);
		blacklist->urls = (PURL *)realloc(blacklist->urls,
			blacklist->size * sizeof(PURL));
		if (blacklist->urls == NULL)
		{
			fprintf(stderr, "error: failed to reallocate memory\n");
			exit(EXIT_FAILURE);
		}
	}

	blacklist->urls[blacklist->length++] = url;
	printf("black : %s\n", url->domain);
}

/*
*(�˻���)������Ʈ�� �����մϴ�.
*/
void BlackListSort(PBLACKLIST blacklist)
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* ������Ʈ�� ���� URL�� ��ġ��Ű���ϴ�.
*/
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)
{
	int lo = 0, hi = ((int)blacklist->length) - 1;

	while (lo <= hi)
	{
		INT mid = (lo + hi) / 2;
		int cmp = UrlMatch(url, blacklist->urls[mid]);
		if (cmp > 0)
		{
			hi = mid - 1;
		}
		else if (cmp < 0)
		{
			lo = mid + 1;
		}
		else
		{
			return TRUE;
		}
	}
	return FALSE;
}


/*
* ���Ϸκ��� URL�� ������ �о�ɴϴ�.
*/
void BlackListRead(PBLACKLIST blacklist, const char *filename)
{
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");

	if (file == NULL)
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}

	// ���Ͽ��� URL�� �а� ������Ʈ�� �߰��մϴ�.
	while (TRUE)
	{
		while (isspace(c = getc(file)))
			;
		if (c == EOF)
		{
			break;
		}
		if (c != '-' && !isalnum(c))
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			if (c == EOF)
			{
				break;
			}
			continue;
		}
		i = 0;
		domain[i++] = (char)c;
		while ((isalnum(c = getc(file)) || c == '-' || c == '.') && i < MAXURL)
		{
			domain[i++] = (char)c;
		}
		domain[i] = '\0';
		j = 0;
		if (c == '/')
		{
			while (!isspace(c = getc(file)) && c != EOF && j < MAXURL)
			{
				uri[j++] = (char)c;
			}
			uri[j] = '\0';
		}
		else if (isspace(c))
		{
			uri[j] = '\0';
		}
		else
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			continue;
		}

		printf("ADD %s/%s\n", domain, uri);

		url = (PURL)malloc(sizeof(URL));
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1) * sizeof(char));
		url->uri = (char *)malloc((j + 1) * sizeof(char));
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];
		}
		url->domain[j] = '\0';

		BlackListInsert(blacklist, url);
	}

	fclose(file);
	return;

memory_error:
	fprintf(stderr, "error: memory allocation failed\n");
	exit(EXIT_FAILURE);
}

/*
* Attempt to parse a URL and match it with the blacklist.
*
* BUG:
* - This function makes several assumptions about HTTP requests, such as:
*      1) The URL will be contained within one packet;
*      2) The HTTP request begins at a packet boundary;
*      3) The Host header immediately follows the GET/POST line.
*   Some browsers, such as Internet Explorer, violate these assumptions
*   and therefore matching will not work.
*/

//Blacklist�� packet�� URL������ ��ġ�ϴ��� ã�Ƴ��ϴ�.
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len)
{
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	URL url = { domain, uri };
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;
	FILE *log;
	
	//log�� �ð��� ����� ���� ���� ����
	struct tm *t;
	time_t timer;

	//URL�� �������� ��ȯ�ϱ� ���� �����ϱ� ���� ����
	char urlstr[20];

	timer = time(NULL);		//���� �ð��� �� ������ ���ɴϴ�.
	t = localtime(&timer); //�� ������ �ð��� �и��Ͽ� ����ü�� �ֽ��ϴ�.


	if (len <= sizeof(post_str) + sizeof(http_host_str))
	{
		return FALSE;
	}
	if (strncmp(data, get_str, sizeof(get_str) - 1) == 0)
	{
		i += sizeof(get_str) - 1;
	}
	else if (strncmp(data, post_str, sizeof(post_str) - 1) == 0)
	{
		i += sizeof(post_str) - 1;
	}
	else
	{
		return FALSE;
	}

	for (j = 0; i < len && data[i] != ' '; j++, i++)
	{
		uri[j] = data[i];
	}
	uri[j] = '\0';
	if (i + sizeof(http_host_str) - 1 >= len)
	{
		return FALSE;
	}

	if (strncmp(data + i, http_host_str, sizeof(http_host_str) - 1) != 0)
	{
		return FALSE;
	}
	i += sizeof(http_host_str) - 1;

	for (j = 0; i < len && data[i] != '\r'; j++, i++)
	{
		domain[j] = data[i];
	}
	if (i >= len)
	{
		return FALSE;
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		// Nice try...
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';

	// Reverse the domain:
	for (i = 0; i < j / 2; i++)
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}

	// blacklist�� url���� ã���ϴ�.:
	result = BlackListMatch(blacklist, &url);

	// ����� ����մϴ�.
	console = GetStdHandle(STD_OUTPUT_HANDLE);


	//blacklist���� url�� ��ġ�ϴ� ����� ã�´ٸ� if�������� ���ϴ�.
	if (result)
	{
		//�ٽ� domain�� �������� �����մϴ�.
		for (i = 0; i < j / 2; i++)
		{
			char t = domain[i];
			domain[i] = domain[j - i - 1];
			domain[j - i - 1] = t;
		}
		//BLOCKED��� �ؽ�Ʈ�� ����ݴϴ�.
		//�� �ڴ� log.txt���Ͽ� �ð��� URL������ ����ݴϴ�.
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		log = fopen("log.txt", "w");
		fprintf(log, "Time : %s URL : %s\n", timeToString(t), url.domain);
		printf("Time : %s URL : %s \n", timeToString(t), url.domain);
		puts("BLOCKED!");
		
		fclose(log);

	}
	else
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;
}

//�ð��� ã�Ƴ��� �Լ��Դϴ�.
char* timeToString(struct tm *t) {
	static char s[20];

	sprintf(s, "%04d-%02d-%02d %02d:%02d:%02d",
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec
	);

	return s;
}

/*
* URL ��
*/
int __cdecl UrlCompare(const void *a, const void *b)
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);
}

/*
* URL ��ġ
*/
int UrlMatch(PURL urla, PURL urlb)
{
	UINT16 i;

	for (i = 0; urla->domain[i] && urlb->domain[i]; i++)
	{
		int cmp = (int)urlb->domain[i] - (int)urla->domain[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->domain[i] == '\0' && urlb->domain[i] != '\0')
	{
		return 1;
	}

	for (i = 0; urla->uri[i] && urlb->uri[i]; i++)
	{
		int cmp = (int)urlb->uri[i] - (int)urla->uri[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->uri[i] == '\0' && urlb->uri[i] != '\0')
	{
		return 1;
	}
	return 0;
}
