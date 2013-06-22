
CRYPTOPP_DIR=/usr/local/Cellar/cryptopp/5.6.1
#POCO_DIR=/usr/local/Cellar/poco/1.4.6
CC=g++
CFLAGS=-c -Wall -shared
LDFLAGS=-I$(CRYPTOPP_DIR)/include -L$(CRYPTOPP_DIR)/lib -lcryptopp
#LDFLAGS=-I$(POCO_DIR)/include/ -L$(POCO_DIR)/lib -lPocoFoundation
SOURCES=src/base.cpp src/encrypt.cpp src/decrypt.cpp src/rncryptor.cpp src/tests.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=rncryptor-test

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
