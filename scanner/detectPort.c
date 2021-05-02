#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void getTime(char *buf)
{
	time_t timep;   
	struct tm *p; 
	char temp[81] = {0};

	time(&timep);   
	p = localtime(&timep);
	//printf("%d-%d-%d %d:%d:%d\n", (1900 + p->tm_year), ( 1 + p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec); 	

	memset(buf,0,sizeof(buf));
	memset(temp,0,sizeof(temp));	
	sprintf(temp,"%d",(1900 + p->tm_year));
	strcat(buf,temp);
	strcat(buf,"-");

	memset(temp,0,sizeof(temp));	
	sprintf(temp,"%d",(1 + p->tm_mon));
	strcat(buf,temp);
	strcat(buf,"-");

	memset(temp,0,sizeof(temp));	
	sprintf(temp,"%d",(p->tm_mday));
	strcat(buf,temp);
	strcat(buf," ");

	memset(temp,0,sizeof(temp));	
	sprintf(temp,"%d",p->tm_hour);
	strcat(buf,temp);
	strcat(buf,":");

	memset(temp,0,sizeof(temp));	
	sprintf(temp,"%d", p->tm_min );
	strcat(buf,temp);
	strcat(buf,":");

	memset(temp,0,sizeof(temp));	
	sprintf(temp,"%d", p->tm_sec );
	strcat(buf,temp);
	strcat(buf,"\n");

}

void *detectHostAndport(void *arg)
{
	char *ip = (char *)arg;
	int port_open_cnt = 0;

	unsigned int port;

	unsigned int start_port = 1;
	unsigned int end_port = 1024;

	unsigned int ip_buf;
	inet_pton(AF_INET, ip, &ip_buf);

	/*创建TCP套接字*/
	int sockfd = 0;

	/*设置要连接的IP地址*/
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = ip_buf;

	int errlog = -1;
	struct servent *se = NULL;

	//设置时间戳,通过扫描的时间长短来判断主机是否存活
	struct timeval starttime,endtime;
	double timeuse;
	
        //获取开始时间戳	
	gettimeofday(&starttime,0);

	int fd = -1;

	char path[255] = {0};
	char buf[255] = {0};
	char port_str[81] ={0};

	for(port=start_port;port<=end_port;port++)
	{
		//printf("port = %d\n",port);
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if(sockfd < 0)
		{
			perror("socket");
			exit(-1);
		}

		server_addr.sin_port = htons(port);
		errlog = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr) );
		if(errlog != 0)
		{
			//端口未打开,连接失败
			close(sockfd);
		}	
		else
		{
			port_open_cnt++;
			if(port_open_cnt == 1)
			{
	
								
				memset(buf,0,sizeof(buf));
				memset(path,0,sizeof(path));
				strcat(path,"./ScanIPFiles/");
				strcat(path,ip);


				fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0777);
				if(fd == -1)
				{
					perror("open");
					return NULL;
				}

				//有端口开放主机存活
				
				//printf("\nIP:%s\nHost UP!!!\n",ip);
				strcat(buf,"IP:");
				strcat(buf,ip);
				strcat(buf,"\nHost is up!   ");
				write(fd, buf, strlen(buf));

				//写入主机名
				memset(buf,0,sizeof(buf));
				strcat(buf,"HostName:");

				struct hostent *hptr;
				if((hptr=gethostbyaddr((void *)&server_addr.sin_addr, 4 ,AF_INET)) == NULL)
				{
					printf("gethostnamebyaddr error for addr:%s\n",ip);
					printf("please add this ip into /etc/hosts\n");
					return NULL;
				}
				strcat(buf,hptr->h_name);
				strcat(buf,"\n");
				write(fd, buf, strlen(buf));

				//写入时间
				memset(buf,0,sizeof(buf));
				getTime(buf);
				write(fd, buf, strlen(buf));


				//struct hostent *hptr;
				//struct sockaddr_in saddr;
				//inet_aton(ip, &saddr.sin_addr);
					

				//printf("ip:%s, hostname:\n",hptr->h_name);
				//printf("port\tstate\tservice\n");
				
				memset(buf,0,sizeof(buf));
				strcat(buf,"port\tstate\tservice\n");
				write(fd, buf, strlen(buf));
			}
			//端口开放,输出信息
			//printf("%d/tcp\topen\t",port);
		
			memset(buf,0,sizeof(buf));
			sprintf(port_str,"%d",port);
			strcat(buf, port_str);
			strcat(buf,"/tcp\topen\t");

			se = getservbyport(htons(port),"tcp");
			if(!se) 
			{
				//printf("unknown");
				strcat(buf,"unknown\n");
			}
			else 
			{
				//printf("%s",se->s_name);
				strcat(buf,se->s_name);
				strcat(buf,"  ");
				int i = -1;	
				for(i=0;se->s_aliases[i];i++)
				{
					//printf(" %s",se->s_aliases[i]);
					strcat(buf,se->s_aliases[i]);
					strcat(buf,"  ");
				}
				strcat(buf,"\n");
			}

			write(fd, buf, strlen(buf));

			//printf("\n");
			close(sockfd);
		}


		gettimeofday(&endtime,0);
		timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
		timeuse /=1000;
		
		if(timeuse > 4000) 
		{
			//printf("timeout\n");
			return NULL;
		}




	}
	

	gettimeofday(&endtime,0);
	timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
	timeuse /=1000;
	//printf("Cost time: %f ms\n",timeuse);

	char time[81] = {0};
	sprintf(time,"%f",timeuse);

	memset(buf,0,sizeof(buf));
	strcat(buf,"Cost time: ");
	strcat(buf, time);
	strcat(buf,"ms\n\n");

	write(fd,buf,strlen(buf)); 
	close(fd);
	return NULL;
}

int main()
{
	unsigned start_port = 1;
	unsigned end_port = 1000;

	char ip[255][81] = {0} ;
	
	char ip_pre3[81] = "192.168.239.";
	char ip_last1[81] = {0};
	int i;
	
	pthread_t tid[255];
	int cnt = 0;

	for(i=1;i<=254;i++)
	{
		memset(ip[cnt],0,sizeof(ip[cnt]));
		memset(ip_last1,0,sizeof(ip_last1));
		
		strcat(ip[cnt],ip_pre3);
		sprintf(ip_last1, "%d", i);		
		strcat(ip[cnt],ip_last1);

		pthread_create(&tid[cnt], NULL, (void *)detectHostAndport,(void *)&ip[cnt]);
				
		pthread_detach(tid[cnt]);


		cnt++;
	}
	sleep(4);

	//打印输出记录文件中的信息
	printf("\nShow Hosts:\n\n");
	system("cat ./ScanIPFiles/192.*");

	return 0;
}
