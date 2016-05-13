CC=g++
CPFLAGS=-g -Wall
LDFLAGS= -lpcap
SRC= wiretap.cc 
OBJ=$(SRC:.cc=.o)
BIN=wiretap

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
