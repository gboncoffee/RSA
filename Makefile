
all: rsa

rsa: rsa.c
	gcc rsa.c -o rsa -lcrypto

clean:
	rm -f rsa *.o
