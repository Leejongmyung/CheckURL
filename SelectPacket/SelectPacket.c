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
* URL과 블랙리스트 구조체입니다.
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
* 패킷을 미리 제작합니다.
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
* Blockpage시 보여줄 페이지를 미리 만듭니다.
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
 Packet을 자르고 보내기 위한 main함수
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



	//블랙리스트 초기화 합니다.
	blacklist = BlackListInit();

	//BlackList를 읽어옵니다.
	BlackListRead(blacklist, "mal_site.txt");
	
	//BlackList를 정렬합니다.
	BlackListSort(blacklist);
	
	//미리 만들어진 패킷을 초기화합니다.
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);
	if (blockpage == NULL)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	//PacketInit를 보낼 패킷으로 초기화합니다.
	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);				//blockpage의 헤더중 ip프로토콜의 길이를 네트워크 형식에 맞게 전달한다.
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;									//데이터를 목적지인 7계층으로 바로 전달합니다.
	blockpage->header.tcp.Ack = 1;									
	
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);	//blockpage의 데이터에 block_data를 집어넣습니다.
	
	//PacketInit를 reset(재설정)으로 초기화합니다.
	PacketInit(reset);												
	reset->tcp.Rst = 1;												//재설정이다. 양 방향에서 동시에 일어나는 비정상적인 연결 끊기입니다.
	reset->tcp.Ack = 1;												//보낸사람 Sequence Number에 TCP의 길이 또는 데이터 양을 더한 것과 같은 ACK 전송해 줍니다.
	
	//PacketInit를 연결을 끝내주도록 초기화합니다.
	PacketInit(finish);												//Packet을 초기화 해 줍니다.
	finish->tcp.Fin = 1;											//연결을 종료 요청이다. 정상적인 종료를 의미합니다.
	finish->tcp.Ack = 1;											//보낸사람 Sequence Number에 TCP의 길이 또는 데이터 양을 더한 것과 같은 ACK 전송해 줍니다.

	// Divert device를 조건에 따라 열기
	handle = WinDivertOpen(
		"outbound && "              // 나가는 것을 잡습니다.
		"ip && "                    // IPv4를 해줍니다.
		"tcp.DstPort == 80 && "     // HTTP만 잡는다는 의미입니다. (포트 80)
		"tcp.PayloadLength > 0",    // TCP데이터의 길이가 0 이상인 것만 잡는다는 의미입니다.
		WINDIVERT_LAYER_NETWORK,    // 네트워크 계층에서 잡습니다.
		priority,					//우선순위는 404(임의)입니다.
		0 //플래그는 0으로 설정하여 줍니다.
	);
	
	//핸들값이 반환되었는지 확인합니다.
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	//핸들값이 정상적으로 반환되었음을 의미합니다.
	printf("OPENED WinDivert\n");

	// 메인 루프를 시작합니다.
	while (TRUE)
	{
		//패킷을 수신한다.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		//WinDivert Helper 구문 분석합니다.
		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char *)payload, (UINT16)payload_len))
		{
			// packat의 URL이이 블랙리스트와 일치하지 않을 때 간단히 재 삽입 해줍니다.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// URL이 블랙리스트와 일치한다면 TCP를 차단합니다.

		// (1) 서버에 TCP RST를 보내주어 연결을 끊어주는 부분입니다.
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

		// (2) 브라우저에 blockpage를 보내주는 부분입니다.
		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;    
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))// 주입된 총 바이트 수, 필요하지 않은 경우에는 NULL을 넣어줄 수 있습니다.
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) 브라우저에 TCP FIN 플래그를 보내주어 연결을 닫아주는 부분입니다.
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
* 패킷을 초기화합니다.
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
* 블랙리스트를 초기화합니다.
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
* 블랙리스트에 url을 집어넣습니다.
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
*(검색용)블랙리스트를 정렬합니다.
*/
void BlackListSort(PBLACKLIST blacklist)
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* 블랙리스트에 대한 URL을 일치시키ㅂ니다.
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
* 파일로부터 URL의 정보를 읽어옵니다.
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

	// 파일에서 URL을 읽고 블랙리스트에 추가합니다.
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

//Blacklist와 packet의 URL정보가 일치하는지 찾아냅니다.
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
	
	//log에 시간을 남기기 위한 변수 선언
	struct tm *t;
	time_t timer;

	//URL을 역순으로 변환하기 전에 저장하기 위한 변수
	char urlstr[20];

	timer = time(NULL);		//현재 시간을 초 단위로 얻어옵니다.
	t = localtime(&timer); //초 단위의 시간을 분리하여 구조체에 넣습니다.


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

	// blacklist를 url에서 찾습니다.:
	result = BlackListMatch(blacklist, &url);

	// 결과를 출력합니다.
	console = GetStdHandle(STD_OUTPUT_HANDLE);


	//blacklist에서 url과 일치하는 결과를 찾는다면 if문안으로 들어갑니다.
	if (result)
	{
		//다시 domain을 역순으로 정렬합니다.
		for (i = 0; i < j / 2; i++)
		{
			char t = domain[i];
			domain[i] = domain[j - i - 1];
			domain[j - i - 1] = t;
		}
		//BLOCKED라는 텍스트를 띄워줍니다.
		//그 뒤는 log.txt파일에 시간과 URL정보를 담아줍니다.
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

//시간을 찾아내는 함수입니다.
char* timeToString(struct tm *t) {
	static char s[20];

	sprintf(s, "%04d-%02d-%02d %02d:%02d:%02d",
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec
	);

	return s;
}

/*
* URL 비교
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
* URL 일치
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
