#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

void ShowMacAddr(char * src_mac, char * dst_mac);

void Decode_IP_Packet(unsigned char * pData);

void Decode_TCP_Packet(unsigned char * pData, int TCPTotalLen);

void Decode_UDP_Packet(unsigned char * pData, int UPPTotalLen);

void Decode_ICMP_Packet(unsigned char * pData, int ICMPTotalLen);

void Decode_Data(unsigned char * pData, int dataLen);

void showHexcode(unsigned char *buf,int len);

typedef struct _IPHeader   //IP数据报头部
{
	unsigned char   iphVerLen;         //版本号和头部长度(各占4位)
	unsigned char   ipTOS;             //服务类型
	unsigned short  ipLength;          //封包总长度,即整个IP报的长度
	unsigned short  ipID;              //封包标识
	unsigned short  ipFlags;           //标志
	unsigned char   ipTTL;             //生存时间,TTL
	unsigned char   ipProtocol;        //协议,可能是TCP,UDP,ICMP等
	unsigned short  ipChecksum;        //检验和
	unsigned int    ipSource;          //源IP地址
	unsigned int    ipDestination;     //目的IP地址
} IPHeader;

typedef struct _TCPHeader //TCP报文头部
{
	unsigned short   sourcePort;       //源端口
	unsigned short   destinationPort;  //目的端口
	unsigned int     seqNum;           //序列号
	unsigned int     ackNum;           //确认号
	unsigned char    dataoff;          //数据偏移,高四位表示首部长度
	unsigned char    flags;            //低六位分别表示标志位为: URG, ACK, PSH, RST, SYN, FIN.
	unsigned short   windows;          //窗口大小
	unsigned short   checksum;         //校验和
	unsigned short   urgentPointer;    //紧急数据指针
} TCPHeader;

typedef struct _UDPHeader //UDP报文头部
{
	unsigned short   sourcePort;       //源端口
	unsigned short   destinationPort;  //目的端口
	unsigned short   len;              //数据长度
	unsigned short   checksum;         //检验和
} UDPHeader;

typedef struct _ICMPHeader //ICMP报文头部
{
	unsigned char    type;             //类型
	unsigned char    code;             //代码
	unsigned short   checksum;         //校验和
	unsigned short   id;               //标识符
	unsigned short   seqNum;           //序列号
	unsigned long    timestamp;        //时间戳
} ICMPHeader;


void Decode_ICMP_Packet(unsigned char * pData, int ICMPTotalLen)
{
	ICMPHeader * pICMPHdr = (ICMPHeader *)pData;

	printf(".........................................................................\n");
	printf("ICMP Header:\n");

	//类型
	printf("类型:%d\n", pICMPHdr->type);

	//代码
	printf("代码:%d\n", pICMPHdr->code);
	
	//校验和
	printf("校验和:%#x\n", ntohs(pICMPHdr->checksum));
	
	//标识符
	printf("标识符:%u\n", ntohs( pICMPHdr->id));
	
	//序列号
	printf("序列号:%u\n", ntohs(pICMPHdr->seqNum));

	//时间戳
	//printf("时间戳:\n");
		
	//处理数据
	Decode_Data(pData+16, ICMPTotalLen-16);
}

void Decode_Data(unsigned char * pData, int dataLen)
{
	int i;

	printf(".........................................................................\n");
	printf("Show Data(Len=%d):\n",dataLen);

	for( i=1; i<=dataLen; i++)
	{
		if(pData[i-1] <= 0x1f || pData[i-1] >= 0x7f)	printf(".");
		else	printf("%c",pData[i-1]);
		if( (i%81) == 0) printf("\n");
	}
	printf("\n");
}

void Decode_TCP_Packet(unsigned char * pData,int TCPTotalLen)
{
	TCPHeader * pTCPHdr  = (TCPHeader * )pData;

	printf(".........................................................................\n");
	printf("TCP Header:\n");

	//源端口和目的端口
	printf("  源端口:%u\n", ntohs( pTCPHdr->sourcePort));
	printf("目的端口:%u\n", ntohs( pTCPHdr->destinationPort));
	
	//序列号和确认号
	printf("序列号: %u\n", ntohl(pTCPHdr->seqNum));
	printf("确认号: %u\n", ntohl(pTCPHdr->ackNum));

	//TCP首部长度
	unsigned int TCPHeadLen = ( pTCPHdr->dataoff>>4 & 0x0f) *4;
	printf("TCP首部长度:%u 字节\n", TCPHeadLen);

	//6个标志位
	printf("6个标志位:\n");
	printf("\tURG:");
	printf("\t%s", ( ( pTCPHdr->flags & 0x20) == 0x20) ? "set\n" : "Not set\n");
	printf("\tACK:");
	printf("\t%s", ( ( pTCPHdr->flags & 0x10) == 0x10) ? "set\n" : "Not set\n");
	printf("\tPSH:");
	printf("\t%s", ( ( pTCPHdr->flags & 0x08) == 0x08) ? "set\n" : "Not set\n");
	printf("\tRST:");
	printf("\t%s", ( ( pTCPHdr->flags & 0x04) == 0x04) ? "set\n" : "Not set\n");
	printf("\tSYN:");
	printf("\t%s", ( ( pTCPHdr->flags & 0x02) == 0x02) ? "set\n" : "Not set\n");
	printf("\tFIN:");
	printf("\t%s", ( ( pTCPHdr->flags & 0x01) == 0x01) ? "set\n" : "Not set\n");

	//窗口大小
	printf("窗口大小:%u\n", ntohs(pTCPHdr->windows));

	//检验和
	printf("检验和:%#x\n", ntohs(pTCPHdr->checksum));
	
	//紧急指针
	printf("紧急指针:%u\n", ntohs(pTCPHdr->urgentPointer));

	//处理数据
	Decode_Data(pData+TCPHeadLen, TCPTotalLen-TCPHeadLen);
}

void Decode_UDP_Packet(unsigned char * pData, int UDPTotalLen)
{
	UDPHeader * pUDPHdr = (UDPHeader * )pData;

	printf(".........................................................................\n");
	printf("UDP Header:\n");
	
	//源端口
	printf("源端口:%u\n", ntohs( pUDPHdr->sourcePort) );

	//目的端口
	printf("目的端口:%u\n", ntohs( pUDPHdr->destinationPort) );

	//数据长度
	unsigned int dataLen = ntohs( pUDPHdr->len);
	printf("数据长度:%u\n", dataLen);

	//校验和
	printf("检验和:%#x\n", ntohs( pUDPHdr->checksum));
	
	//处理数据
	Decode_Data(pData+8, dataLen);
}


void Decode_IP_Packet(unsigned char * pData)
{
	IPHeader * pIPHdr = (IPHeader * )pData;
	unsigned char buf = pData[0];

	printf(".........................................................................\n");
	printf("IP Header:\n");
	
	//IP版本
	int IPVersion;
	if((buf & 0xf0) == 0x40)	IPVersion = 4;
	else if((buf & 0xf0) == 0x60)		IPVersion = 6;
	printf("IP版本 :%d\n",IPVersion);

	//IP首部长度
	unsigned int IPHeadLen = (unsigned char)(buf & 0x0f) * 4;
	printf("首部长度: %d 字节\n", IPHeadLen);

	//IP数据报总长度
	unsigned int IPTotalLen = ntohs(pIPHdr->ipLength);
	printf("IP数据报总长度: %#x (%d)  \n", IPTotalLen , IPTotalLen);

	//IP数据报标识
	printf("IP数据报标识: %#x (%d)  \n", ntohs(pIPHdr->ipID), ntohs(pIPHdr->ipID));
	
	//IP标志
	printf("IP标志:\n");
	printf("\tReserved bit: ");
	printf("\t\t%s", ( ( ntohs( pIPHdr->ipFlags) & 0x8000) == 0x8000) ? "set\n" : "Not set\n");
	printf("\tDon't fragment(DM): ");
	printf("\t%s",   ( ( ntohs( pIPHdr->ipFlags) & 0x4000) == 0x4000) ? "set\n" : "Not set\n");
	printf("\tMore fragment(FM): ");
	printf("\t%s",   ( ( ntohs( pIPHdr->ipFlags) & 0x2000) == 0x2000) ? "set\n" : "Not set\n");

	//IP片偏移
	printf("IP片偏移: %#x (%d) \n", ntohs(pIPHdr->ipFlags) & 0x1fff , ntohs(pIPHdr->ipFlags) & 0x1fff );

	//生存时间
	printf("生存时间: %d \n",pIPHdr->ipTTL);
	
	//首部校验和
	printf("首部校验和: %#x \n", ntohs(pIPHdr->ipChecksum) );

	//源IP和目的IP
	struct in_addr source, dest;
	char szSourceIp[32], szDestIp[32];

	source.s_addr = pIPHdr->ipSource;
	dest.s_addr = pIPHdr->ipDestination;
	strcpy(szSourceIp,inet_ntoa(source));
	strcpy(szDestIp,inet_ntoa(dest));
	printf("  源IP: %s\n",szSourceIp);
	printf("目的IP: %s\n",szDestIp);

	//协议类型
	switch(pIPHdr->ipProtocol)
	{
		case 1:   //ICMP
			printf("协议:ICMP\n");
			Decode_ICMP_Packet( pData+IPHeadLen, IPTotalLen-IPHeadLen );
			break;
		case 6:   //TCP
			printf("协议:TCP\n");
			Decode_TCP_Packet( pData+IPHeadLen, IPTotalLen-IPHeadLen );
			break;
		case 17:  //UDP
			printf("协议:UDP\n");
			Decode_UDP_Packet( pData+IPHeadLen, IPTotalLen-IPHeadLen );
			break;
		default:
			printf("未知协议...\n");
			break;
	}
}

void showHexcode(unsigned char *buf,int len)
{
	printf(".........................................................................\n");
	printf("\n十六进制显示(TotalLen=%d):\n",len);
	unsigned char uChar;
	int i;
	char temp[10];

	for( i=1; i<=len; i++)
	{
		memset(temp,0,sizeof(temp));
		sprintf(temp,"%2x",buf[i-1]);

		if(temp[0] == ' ') temp[0] = '0';
		printf("%s ",temp);
		if((i % 8) == 0) printf("   ");
		if((i % 16) == 0) printf("\n");
	}
	printf("\n");
}

void ShowMacAddr(char * src_mac, char * dst_mac)
{
	printf("\n-------------------------------------------------------------------------\n");
	printf("MAC:   Src:   %s  ---> Dst:   %s  \n",src_mac,dst_mac);
}

int main(int argc, char *argv[])
{
	/*创建链路层原始套接字*/
	unsigned char buf[1024] = "";
	int ret_len = -1;

	int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	printf("开始探测数据包...\n");
	while(1)
	{
		unsigned char src_mac[18] = "";
		unsigned char dst_mac[18] = "";

		//获取链路层的数据帧
		ret_len = recvfrom(sock_raw_fd, buf ,sizeof(buf), 0, NULL, NULL);
		
		//从buf中提取目的MAC及源MAC,依据以太网报文格式解析数据包
		sprintf(dst_mac,"%02x:%02x:%02x:%02x:%02x:%02x",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
		sprintf(src_mac,"%02x:%02x:%02x:%02x:%02x:%02x",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
			
		//if(!strcmp(dst_mac,"00:0c:29:f4:f6:a7") || !strcmp(src_mac,"00:0c:29:f4:f6:a7")) ;
		//else continue;


		//判断是不是IP数据报
		if(buf[12] == 0x08 && buf[13]==0x00)
		{
			//IP数据类型
			ShowMacAddr(src_mac, dst_mac);

			unsigned char * IPstartaddr = &buf[14];
			Decode_IP_Packet(IPstartaddr);

			showHexcode(buf, ret_len);
		}
		else if(buf[12] == 0x08 && buf[13] == 0x06)
		{
			//ARP数据类型
			//printf("ARP packet :\n");
			//printf("MAC:%s>>%s\n",src_mac,dst_mac);
		}
		else if(buf[12] == 0x80 && buf[13] == 0x35)
		{
			//ARPA数据类型
			//printf("ARPA packet :\n");
			//printf("MAC:%s>>%s\n",src_mac,dst_mac);
		}
	}

	return 0;
}
