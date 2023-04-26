本实验室的学习目标是让学生掌握vpn背后的网络和安全技术。为了实现这一目标，学生将被要求实现一个简单的TLS/SSL VPN。虽然这个VPN很简单，但它确实包含了VPN的所有基本元素。TLS/SSLvpn的设计和实现体现了许多安全原则，包括以下几点：




编写了 docker-compose.yml

启动
dcbuild
dcup


综上所述，通过执行以上操作，我们完成了**VM Setup**任务


编写完后 
chmod a+x filename //给所有用户读写运行的权限


![](attachments/Pasted%20image%2020230425161340.png)

![](attachments/Pasted%20image%2020230425161353.png)


**Step 1:****修改vpnserver文件并执行：**


在 client 中
etc/hosts 
加上
```
10.0.2.8 www.hjf.com
```



![](attachments/Pasted%20image%2020230425171643.png)



![](attachments/Pasted%20image%2020230425171712.png)

# TLS

```
openssl req -newkey rsa:2048 -sha256 \
-keyout new-server-key.pem -out new-server-csr.pem \
-subj "/CN=www.hjf.com/O=hjf Inc./C=US/serialNumber=1234567890" \
-passout pass:seed

```


```
openssl ca -config openssl.cnf -policy policy_anything -md sha256 -days 365 -in new-server-csr.pem -out new-server-cert.pem -batch -cert ./cacert.pem -keyfile ./cakey.pem
```

![](attachments/Pasted%20image%2020230425195030.png)



修改了server文件后
make 

在Server 上 

./tlsserver 

在 Client 上
./tlsclient www.hjf.com 4433

![](attachments/Pasted%20image%2020230425200028.png)


![](attachments/Pasted%20image%2020230425200043.png)

建立了连接



###  这里，我们还需要使用wireshark 抓包看看，是否加密

查看到了双方建立TCP链接的过程，查看数据包，确实被加密。

综上所述，通过执行以上操作，我们完成了**Encrypting the Tunnel**任务


查看端口进程
netstat -lnp | grep :4433

kill -9 《PID》