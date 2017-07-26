CC = gcc
#CC = arm-linux-gnueabi-gcc
LIBS = -lm -lpcap
FLAGS =
BIN_DIR=../bin
lnc: main.o bmppp.o
	$(CC) main.o bmppp.o $(LIBS) -o $(BIN_DIR)/$@ $(FLAGS)
$(BIN_DIR)/main.o:
	$(CC) main.c -c -o $(BIN_DIR)/$@ 
$(BIN_DIR)/bmppp.o:
	$(CC) bmppp.c -c -o $(BIN_DIR)/$@
deploy: lnc
	scp $(BIN_DIR)lnc root@192.168.0.1:
clean:
	rm $(BIN_DIR)/*.o
	
	
