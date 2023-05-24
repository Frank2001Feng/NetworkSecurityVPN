

---
Task1~6 参照 `../reference/VPN.pdf`

快速复现可以直接查看：`实验快速复现`

---

# 实验演示
虚拟专用网（VPN）用于创建计算机通信的私有范围或将私有网络的安全扩展提供到不安全的网络中。VPN是一种被广泛使用的安全技术。VPN可以建立在IPSec或TLS/SSL（传输层安全/安全套接字层）上。这是两种完全不同的构建vpn的方法。在这个实验室中，我们专注于基于TLS/SSLl的VPN。这种类型的vpn通常被称为TLS/SSL VPNs 

我们将实现一个简单的TLS/SSL VPN。虽然这个VPN很简单，但它确实包含了VPN的所有基本元素。TLS/SSLvpn的设计和实现体现了许多安全原则，包括以下几点：

- Virtual Private Network
- TUN/TAP, and IP tunneling
- Routing
- Public-key cryptography, PKI, and X.509 certifificate
- TLS/SSL programming
- Authentication


# Task 1: VM Setup

我们将在计算机（客户端）和网关之间创建一个VPN隧道，允许计算机通过网关安全地访问专用网络。我们至少需要三个VM：VPN客户端（也作为主机U）、VPN服务器（网关）和专用网络中的主机（主机V）。


在实际应用中，VPN客户端和VPN服务器是通过互联网连接的。为了简单起见，我们在这个实验室将这两台机器直接连接到同一个局域网，也就是说，这个局域网模拟互联网。我们将为这个局域网使用“NAT网络”适配器。第三台机器，主机V，是一个专用网络内的计算机。主机U上（专用网外）的用户希望通过VPN隧道与主机V进行通信。为了模拟这种设置，我们通过一个“内部网络”将主机V连接到VPN服务器（也作为一个网关）。在这种设置中，主机V不能直接从互联网访问；也不能直接从主机U访问。

```
使用 docker-compose.yml 构建实验环境
dcbuild
dcup
```

# Task 2: Creating a VPN Tunnel using TUN/TAP
TUN和TAP是虚拟网络内核驱动程序；它们实现了完全由软件支持的网络设备。

TAP（如网络点击）模拟以太网设备，它使用第2层数据包，如以太网帧；
TUN（如网络TUNnel）模拟网络层设备，它使用第3层数据包，如IP数据包。
使用TUN/TAP，我们可以创建虚拟网络接口。

https://www.zhaohuabing.com/post/2020-02-24-linux-taptun/


# Task 3: Encrypting the Tunnel 
此时，我们已经创建了一个IP隧道，但我们的隧道没有受到保护。只有在我们保护了这个隧道之后，我们才能称之为VPN隧道。这就是我们在这个任务中要实现的。为了保护这条隧道，我们需要实现两个目标，保密性和完整性。机密性是通过加密来实现的，即通过隧道的内容被加密。完整性目标确保没有人可以篡改隧道中的流量或启动重放攻击。可以使用消息认证码（MAC）来实现完整性。这两个目标都可以使用传输层协议（TLS）来实现。 

https://cshihong.github.io/2019/05/11/SSL-VPN%E6%8A%80%E6%9C%AF%E5%8E%9F%E7%90%86/


# Task 4: Authenticating the VPN Server 

在建立VPN之前，VPN客户端必须对VPN服务器进行身份验证，以确保该服务器不是一个欺诈性的服务器。另一方面，VPN服务器必须对客户端（即用户）进行身份验证，以确保用户具有访问专用网络的权限。在此任务中，我们实现了服务器身份验证；客户端身份验证在下一个任务中。

验证服务器的一种典型方法是使用公钥证书。VPN服务器需要首先从证书颁发机构（CA）获取一个公钥证书。当客户端连接到VPN服务器时，服务器将使用该证书来证明它是预期的服务器。HTTPS协议使用这种方法来对web服务器进行身份验证，以确保您正在与预期的web服务器对话，而不是假的服务器。

在这个实验室中，MiniVPN应该使用这种方法来验证VPN服务器。我们可以从头开始实现一个认证协议（如TLS/SSL），但幸运的是，openssl已经为我们完成了大部分工作。我们只需要正确配置TLS会话，以便就可以为我们自动进行身份验证。

有服务器身份验证的三个重要步骤： 
(1)验证服务器证书是否有效，
(2)验证服务器是证书的所有者，
(3)验证服务器是预期的服务器（例如，如果用户打算访问example.com，我们需要确保服务器确实是example.com，而不是另一个站点）。
请指出您的程序中哪些代码行执行上述验证。在演示中，您需要演示关于第三次验证的两种不同情况：成功的服务器身份验证，其中服务器是预期服务器，以及失败的服务器身份验证，其中服务器不是预期服务器。

```
在程序异常退出时，查看退出码
echo $?

有点问题，无法正常退出
while(1) 循环，使用呢Ctrl+C 会占用端口，注意 kill 进程
```



# Task 5: Authenticating the VPN Client

```
login 运行后
查看 /etc/shadow 文件，可以看到配置的账号密码
```


访问私有网络中的机器是一种只授予授权用户的特权，而不是授予所有人。因此，只有授权用户才允许与VPN服务器建立VPN隧道。在此任务中，授权用户是那些在VPN服务器上拥有有效帐户的用户。因此，我们将使用标准的密码身份验证来对用户进行身份验证。基本上，当一个用户试图与VPN服务器建立一个VPN隧道时，该用户将被要求提供一个用户名和一个密码。服务器将检查其影子文件（/etc/影子）；如果找到匹配的记录，则对用户进行身份验证，并建立VPN隧道。如果没有匹配，服务器将断开与用户的连接，因此不会建立隧道。有关如何使用影子文件对用户进行身份验证的示例代码，请参阅第3.3节。


# Task 6: Supporting Multiple Clients
在现实世界中，一个VPN服务器通常支持多个VPN隧道。也就是说，VPN服务器允许多个客户端同时连接到它，每个客户端都有自己的VPN隧道（因此也有自己的TLS会话）。我们的MiniVPN应该支持多个客户端。

在一个典型的实现中，VPN服务器进程（父进程）将为每个隧道创建一个子进程（请参见图4）。当一个包来自隧道时，它对应的子进程将获得该包，并将其转发到TUN接口。无论是否支持多个客户端，这个方向都是相同的。这是另一个具有挑战性的方向。当一个数据包到达TUN接口（从专用网络）时，父进程将获得该数据包，现在它需要找出该数据包应该进入哪个隧道。你需要考虑如何实现这个决策逻辑。

一旦做出决定并选择了一个隧道，父进程就需要将数据包发送给所选隧道所附加到的子进程。这就需要IPC（进程间通信）。一个典型的方法是使用管道。我们在第3.4节中提供了一个示例程序来演示如何使用管道进行IPC。

子进程需要监视此管道接口，如果有数据，则从其中读取数据。由于子进程还需要注意来自套接字接口的数据，因此它们需要同时进行处理

--- 
# 实验快速复现  
```c

// download file：miniVPN 
// login your VM
cd miniVPN

/*----------------------------Setup---------------------------------*/
// we can see all settings in docker-compose.yml 
dcbuild 
dcup 

/*--------------------配置 Server & Client，编译代码--------------------*/
/*---------on your VM-------*/
cd  myvpn
// 文件 login.c myvpnserver.c myvpnclient.c Makefile 
// 文件夹 cert_server ca_client

/*--1. 首先，为Server端网站生成新的 CA 证书 （网站 www.hjf.com）--*/
cd cert_server/

// 创建 一张 CA 证书，密码：seed，网站：www.hjf.com
openssl req -newkey rsa:2048 -sha256 \
-keyout new-server-key.pem -out new-server-csr.pem \
-subj "/CN=www.hjf.com/O=hjf Inc./C=US/serialNumber=1234567890" \
-passout pass:seed

openssl ca -config openssl.cnf -policy policy_anything -md sha256 -days 365 -in new-server-csr.pem -out new-server-cert.pem -batch -cert ./cacert.pem -keyfile ./cakey.pem

// 查看新生成的文件：new-
ls

/*--2.为客户创建账户--*/
cd ..
// 为已经写好了程序，编译一下
make 
// 编译出三个文件
// 需要为Client创建登陆的账户，运行 login 文件， 创建 账户：seed 密码：dees
sudo ./login seed dees

/*-----------------------Server---------------------*/
// 登陆 server 可以在 /etc/shadow 文件中查看账户
cd /etc 
nano shodow

/*-----------------------Client---------------------*/
// 为了在vpnclient客户端中可以，可以检索到www.hjf.com 对应的 ipv4地址
// 在 vpnclient 的 /etc/hosts 文件末行 加上 10.0.2.8 www.hjf.com
cd /etc 
nano hosts
// 加上 www.hjf.com 
10.0.2.8 www.hjf.com


/*------------------------前期准备完毕，可以开始跑代码了---------------------*/

// 1. Server 上 运行服务端程序，开始监听
./myvpnserver

// 2. 任意一个 Client 上 运行 客户端程序 输入参数 

./myvpnclient www.hjf.com 4433 seed dees 5
// www.hjf.com ：表示要访问的网站，如不正确，则访问失败
// seed dees ：表示 登陆账密，服务器端要认证
// 5 ：表示在client 上开启了 一个 tun0 端口，设置的 ip 为 192.168.53.5，服务器会使用用到这个信息 fork 创建 pipe 实现多用户访问

//运行上面的命令就可以连接上啦
//当然，我们可以多用户连接

/*-------------------------------测试---------------------------------*/

// 登陆 client 1 2 访问内网 ip
ping 192.168.60.101
ping 192.168.60.102
// client 连接登陆 内网主机
telnet 192.168.60.101
// host-192.168.60.101 上 ping client 的 tun 端口
ping 192.168.53.5
```



查看版本 tls 
```
openssl s_client -help 2>&1 | awk '/-(ssl|tls)[0-9]/{print $1}'
```

[SSL/TLS 1.2 握手交互过程 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/421446218)
