CC = gcc
#CC = arm-linux-gnueabi-gcc
LIBS = -lm -lpcap
FLAGS = -O3
BIN_DIR=../bin
lnc: main.o
	$(CC) main.o $(LIBS) -o $(BIN_DIR)/$@ $(FLAGS)
main.o:
	$(CC) main.c -c -o $@ $(FLAGS)
bmppp.o:
	$(CC) bmppp.c -c -o $@
deploy: lnc
	scp $(BIN_DIR)/lnc root@192.168.0.1:
clean:
	rm *.o
	
	
