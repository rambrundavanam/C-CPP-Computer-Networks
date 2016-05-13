CC=g++
CPFLAGS=-g -Wall
LDFLAGS= -lpcap -lpthread
LIBS_PATH = -L/usr/include/pcap
SRC= portScanner.cc ps_parse.cc ps_lib.cc
OBJ=$(SRC:.cc=.o)
BIN=portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
