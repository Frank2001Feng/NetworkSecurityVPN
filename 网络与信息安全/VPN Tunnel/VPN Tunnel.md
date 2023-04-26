
# 实验目的
这个实验室的目的是帮助学生了解VPN是如何工作的。我们关注一种特定类型的VPN（最常见的类型），它建立在传输层之上。我们将从头开始构建一个非常简单的VPN，并使用这个过程来说明每个VPN技术是如何工作的。一个真正的VPN程序有两个基本的部分，隧道传输和加密。
这个实验室只关注隧道部分，帮助学生理解隧道技术，所以这个实验室的隧道没有加密。还有另一个更全面的VPN实验室，其中包括加密部分。本实验室将涵盖以下主题：

Virtual Private Network

The TUN/TAP virtual interface

IP tunneling

Routing

# 实验环境
我们将在计算机（客户端）和网关之间创建一个VPN隧道，允许计算机通过网关安全地访问专用网络。我们至少需要三台机器：VPN客户端（也作为主机U）、VPN服务器（路由器/网关）和专用网中的主机（主机V）。网络设置如图1所示。

Lab environment setup
![[大三下/网络与信息安全/VPN Tunnel/attachments/setup.png]]

在实际应用中，VPN客户端和VPN服务器是通过互联网连接的。为了简单起见，我们在这个实验室将这两台机器直接连接到同一个局域网，也就是说，这个局域网模拟互联网。

第三台机器，主机V，是一个专用网络内的计算机。主机U上（专用网外）的用户希望通过VPN隧道与主机V进行通信。为了模拟这个设置，我们将主机V连接到VPN服务器（也用作网关）。在这种设置中，主机V不能直接从互联网访问；也不能直接从主机U访问。

```
dcbuild
dcup
dcdown

dockps
docksh [id]
```

![[Pasted image 20230324174742.png]]

# Task 1: Network Setup

Testing.

Please conduct the following testings to ensure that the lab environment is set up correctly:

• Host U can communicate with VPN Server.

• VPN Server can communicate with Host V.

• Host U should not be able to communicate with Host V.

• Run tcpdump on the router, and sniff the traffific on each of the network. Show that you can capture

packets.

1.Client内启动docker，并且ping VPN Server 10.9.0.11，能ping通
![[Pasted image 20230324175049.png]]


2. 进入 server-router，ping Host V （ping 192.168.60.5），都成功 ping 通 

![[Pasted image 20230324175300.png]]


3. client 试一下 ping 192.168.60网段，发现都无法 ping 通
![[Pasted image 20230324175509.png]]

4. 在路由器上运行tcpdump，并嗅探每个网络上的流量。结果如下

tcpdump -i eth0 -n

![[Pasted image 20230324175809.png]]

![[Pasted image 20230324175932.png]]



# Task 2: Create and Configure TUN Interface

改一下代码
```python
#!/usr/bin/env python3  
  
import fcntl  
import struct  
import os  
import time  
from scapy.all import *  
  
TUNSETIFF = 0x400454ca  
IFF_TUN   = 0x0001  
IFF_TAP   = 0x0002  
IFF_NO_PI = 0x1000  
  
# Create the tun interface  
tun = os.open("/dev/net/tun", os.O_RDWR)  
ifr = struct.pack('16sH', b'huang%d', IFF_TUN | IFF_NO_PI)  
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)  
  
# Get the interface name  
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")  
print("Interface Name: {}".format(ifname))  
  
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))  
os.system("ip link set dev {} up".format(ifname))  
  
while True:  
    #time.sleep(10)  
    # Get a packet frrom the tun interface    packet = os.read(tun, 2048)  
    if packet:  
        ip = IP(packet)  
        print(ip.summary())  
        # Send out a spoof packet using the tun interface  
        if ICMP in ip:  
            newip=IP(src=ip.dst,dst=ip.src)  
            newpkt=newip/ip.payload  
            os.write(tun,bytes(newpkt))  
            os.write(tun,b'hjf')  
            print('Send out:')  
            print(IP(bytes(newpkt)).payload)

```

**Task 2.a: Name of the Interface**
![[Pasted image 20230324181414.png]]

![[Pasted image 20230324181439.png]]


**Task 2.b: Set up the TUN Interface**

代码中加入这些 
```
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
```


运行查看效果
![[Pasted image 20230327151622.png]]

![[Pasted image 20230327151712.png]]

查看结果，已配置成功

**Task 2.c: Read from the TUN Interface**

将 tun.py 中的 while 循环改为如下

![[Pasted image 20230327152343.png]]



在 Host U ping 192.168.53.1，tun.py 输出捕获的 ICMP
![[Pasted image 20230327152420.png]]

![[Pasted image 20230327152443.png]]

尝试ping 192.168.60.5、192.168.60.6，发现无法 ping 通且不输出任何东西，说明此时 ICMP 报文并未传送到 tunnel 上。

![[Pasted image 20230327152649.png]]


![[Pasted image 20230327152707.png]]


**Task 2.d: Write to the TUN Interface**

![[Pasted image 20230327154322.png]]

![[Pasted image 20230327154347.png]]

![[Pasted image 20230327154414.png]]


修改一下write内容
![[Pasted image 20230327162651.png]]


可以发现 ICMP 回显请求

![[Pasted image 20230327162853.png]]



# Task 3: Send the IP Packet to VPN Server Through a tunnel 



新建两个py文件


Server 
```python 
#!/usr/bin/env python3
from scapy.all import *
IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
while True:
	data, (ip, port) = sock.recvfrom(2048)
	print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
	pkt = IP(data)
	print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
```

Client 
```python 
#!/usr/bin/env python3  
  
import fcntl  
import struct  
import os  
import time  
from scapy.all import *  

SERVER_PORT=9090
SERVER_IP='10.9.0.11'
IP_A='0.0.0.0'
  
TUNSETIFF = 0x400454ca  
IFF_TUN   = 0x0001  
IFF_TAP   = 0x0002  
IFF_NO_PI = 0x1000  
  
# Create the tun interface  
tun = os.open("/dev/net/tun", os.O_RDWR)  
ifr = struct.pack('16sH', b'huang%d', IFF_TUN | IFF_NO_PI)  
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)  
  
# Get the interface name  
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")  
print("Interface Name: {}".format(ifname))  

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))  
os.system("ip link set dev {} up".format(ifname))  
  
while True:
	# Get a packet from the tun interface
	packet = os.read(tun, 2048)
	if packet:
		# Send the packet via the tunnel
		sock.sendto(packet, (SERVER_IP, SERVER_PORT))


```


分别运行后，在两个运行的地方查看， ICMP 请求包封装到 UDP报文中，并发送给 10.9.0.11 的 9090 端口，而服务器程序监听自己的 9090 端口

ping 192.168.53.1
![[Pasted image 20230327170422.png]]

![[Pasted image 20230327170437.png]]

![[Pasted image 20230327170454.png]]


修改静态路由，再次尝试发现接收成功



# 其他
```
ps aux  # 查看正在运行的程序
```