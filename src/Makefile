CC = gcc
#CC = arm-linux-gnueabi-gcc
LIBS = -lm -lpcap
FLAGS = 
lnc:
	$(CC) main.c $(LIBS) -o $@ $(FLAGS)

deploy: lnc
	scp lnc root@192.168.0.1:

	
