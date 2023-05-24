all: 
	gcc -o login login.c -lcrypt
	gcc -o myvpnclient myvpnclient.c -pthread -lssl -lcrypto 
	gcc -o myvpnserver myvpnserver.c -pthread -lssl -lcrypto -lcrypt
clean: 
	rm myvpnclient myvpnserver

#gcc -o login login.c -lcrypt
#sudo ./login seed dees