CC=g++
CPFLAGS=-g -Wall
LDFLAGS= -lcrypto
SRC= bt_client.cc bt_lib.cc bt_setup.cc 
OBJ=$(SRC:.cc=.o)
BIN=bt_client

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
