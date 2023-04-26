



# 1 Overview
本实验室的目标是帮助学生获得这两种隧道技术的实践经验。本实验室将涵盖以下主题：
• Firewall evasion

• VPN

• Port forwarding

• SSH tunneling
![[大三下/网络与信息安全/Firewall Evasion/attachments/setup.png]]


![[大三下/网络与信息安全/Firewall Evasion/attachments/1.png]]

# 2 Task 0: Get Familiar with the Lab Setup

**Lab task.
Please block two more websites and add the fifirewall rules to the setup fifiles. The choice of
websites is up to you. We will use them in one of the tasks. Keep in mind that most popular websites have multiple IP addresses that can change from time to time. After adding the rules, start the containers, and verify that all the ingress and egress fifirewall rules are working as expected.**

阻止访问www.baidu.com
180.101.50.0/24



Setting up the rule in Iptables for restricting 2 IP address.  Eg: linkedin.com

![[大三下/网络与信息安全/Firewall Evasion/attachments/3.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/4.png]]
Observation: As we can see that now when we are trying to ping nothing appears on the terminal because they are blocked by the default firewall.

禁止访问 seu
```
iptables -A FORWARD -i eth1 -d 58.192.188.0/24 -j DROP
```
![[大三下/网络与信息安全/Firewall Evasion/attachments/5.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/6.png]]



# Task 1: Static Port forwarding 

On docker container A-10.8.0.99

```
ssh -L 0.0.0.0:8000:192.168.20.99.23:23 root@192.168.20.99
```
![[大三下/网络与信息安全/Firewall Evasion/attachments/7.png]]


On docker container A1

```
telnet 10.8.0.99 8000
```
![[大三下/网络与信息安全/Firewall Evasion/attachments/8.png]]

On docker container A2
```
telnet 10.8.0.99 8000
```
![[大三下/网络与信息安全/Firewall Evasion/attachments/9.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/10.png]]

(1) How many TCP connections are involved in this entire process. You should run Wireshark or tcpdump to capture the network traffic, and then point out all the involved TCP connections from the captured traffic.

Ans: 3 TCP connection are involved in this process.

(2) Why can this tunnel successfully help users evade the firewall rule specified in the lab setup?
Ans: Yes, we can use this tunnel to evade the firewall rule. As port 23 is blocked but we can see that port no. 22 is still open, from that port we can establish a SSH connection which act as a tunnel between internal host and internal machine.

Here we can see that that telnet connection is successfully established between internal host and external host via SSH tunnelling mechanism.

# Task 2: Dynamic Port Forwarding

## Task 2.1: Setting Up Dynamic Port Forwarding
On container B
```
ssh -4NT -D 0.0.0.0:8000 seed@10.8.0.99 -f -N

curl -x socks5h://<B’s IP>:<B’s port> <blocked URL>
curl -x socks5h://0.0.0.0:8000 https://www.seu.edu.cn

```

![[大三下/网络与信息安全/Firewall Evasion/attachments/11.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/12.png]]


On container B1
```
curl -x socks5h://192.168.20.99:8000 https://www.seu.edu.cn
```
![[大三下/网络与信息安全/Firewall Evasion/attachments/13.png]]



On container B2
![[大三下/网络与信息安全/Firewall Evasion/attachments/14.png]]

(1) How many TCP connections are involved in this entire process. You should run Wireshark or

tcpdump to capture the network traffic, and then point out all the involved TCP connections from the

captured traffic.

Ans:  Here the actual connection is established by the external machine A. the internal host indirectly establish connection via SSH tunnelling. 

(2) Why can this tunnel successfully help users evade the firewall rule specified in the lab setup?

Ans: The curl commend will be forwarded to the external host to which we have established connection. That command will be used by the external host to fetch information required and it will send it to the internal host.

## Task 2.2:Testing the Tunnel Using Browser

![[大三下/网络与信息安全/Firewall Evasion/attachments/15.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/16.png]]

```
ps -eaf | grep "ssh"
kill id
```


![[大三下/网络与信息安全/Firewall Evasion/attachments/17.png]]


After cleaning up the proxy:

We can see that LinkedIn started working fine again
![[大三下/网络与信息安全/Firewall Evasion/attachments/18.png]]

## Task 2.3:Writing a SOCKS Client Using python 

Container B
```
ssh -4NT -D 0.0.0.0:8000 seed@10.8.0.99 -f -N

nano B_socks_client.py

python3 B_socks_client.py

```

![[大三下/网络与信息安全/Firewall Evasion/attachments/19.png]]

![[A1.png]]



Container B1
```
nano B1_B2_socks_client.py

python3 B1_B2_socks_client.py
```

![[A2.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/20.png]]



on container B2
![[大三下/网络与信息安全/Firewall Evasion/attachments/21.png]]

# Task 3:Comparing SOCKS5 Proxy and VPN 


no VPN 

![[大三下/网络与信息安全/Firewall Evasion/attachments/22.png]]

on container A

```
apt-get update
apt-get install sudo

```


```
sudo ssh -w 0:0 root@192.168.20.99 \
-o "PermitLocalCommand=yes" \
-o "LocalCommand= ip addr add 192.168.53.88/24 dev tun0 && \
ip link set tun0 up" \
-o "RemoteCommand= ip addr add 192.168.53.99/24 dev tun0 && \
ip link set tun0 up"

```

![[大三下/网络与信息安全/Firewall Evasion/attachments/31.png]]



sudo ip tuntap add mode tun tun0
sudo ip addr add 192.168.53.88/24 dev tun0
sudo ip link set tun0 up
ssh -w 0:0 root@192.168.20.99
![[大三下/网络与信息安全/Firewall Evasion/attachments/23.png]]


![[大三下/网络与信息安全/Firewall Evasion/attachments/24.png]]








sudo ip tuntap add dev tun0 mode tun
sudo ip addr add 192.168.53.88/24 dev tun0
sudo ip link set tun0 up



sudo ip tuntap add dev tun0 mode tun
sudo ip addr add 192.168.53.99/24 dev tun0
sudo ip link set tun0 up


![[大三下/网络与信息安全/Firewall Evasion/attachments/41.png]]


sudo ssh -w 0:0 root@192.168.20.99
![[大三下/网络与信息安全/Firewall Evasion/attachments/42.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/43.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/44.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/45.png]]


sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE







ip route show 
![[大三下/网络与信息安全/Firewall Evasion/attachments/46.png]]

sudo ssh -w 0:0 root@10.8.0.99

![[大三下/网络与信息安全/Firewall Evasion/attachments/47.png]]

![[大三下/网络与信息安全/Firewall Evasion/attachments/48.png]]



![[attachments/49.png]]



![[50.png]]