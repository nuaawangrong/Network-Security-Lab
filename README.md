# Network-Security-Lab

## 项目简介
这是NUAA信息安全专业2021年网络安全课设作业。

分别为扫描器和嗅探器，运行环境为Linux。
使用`make`命令进行编译，然后直接运行对应的可执行文件即可。

运行扫描器之前需要自行手动设置局域网的IP地址段，例如`192.168.239.`。



## 实验运行截图

实验截图为相对地址，请下载项目后在本地查看！！！

### 1、scanner(简单网络主机扫描程序)
一个使用C语言编写的在Linux环境下扫描局域网内主机的程序，主要功能为显示局域网内的主机IP地址列表，并显示主机开放的端口。



   运行截图：

   ![1.1-scanner](.\pic\1.1-scanner.png)

   Nmap运行截图：
   ![1.2-nmap](.\pic\1.2-nmap.png)


### 2、sniffer(网络嗅探器)

一个使用C语言编写的在Linux环境下监听网络流量的程序，主要功能为对截取的报文进行解析（支持IP数据包首部解析及TCP、UDP和ICMP协议的数据包内容解析）。



1. ICMP数据包显示

   运行截图：

   ![2.1-sniffer_ICMP](.\pic\2.1-sniffer_ICMP.png)
   
   Wireshark运行截图：

   ![2.2-wireshark_ICMP](.\pic\2.2-wireshark_ICMP.png)

2. UDP数据包显示

   运行截图：

   ![2.3-sniffer_UDP](.\pic\2.3-sniffer_UDP.png)

3. TCP数据包显示

   运行截图：

   ![2.4-sniffer_TCP](.\pic\2.4-sniffer_TCP.png)

   Wireshark运行截图：

   ![2.5-wireshark_TCP](.\pic\2.5-wireshark_TCP.png)

