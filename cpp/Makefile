CC=g++
CFLAGS=-c -Wall
#CFLAGS=-c -Wall -g -rdynamic
LDFLAGS=-I/usr/local/Cellar/cryptopp/5.6.1/include -L/usr/local/Cellar/cryptopp/5.6.1/lib -lcryptopp
#LDFLAGS=-I/usr/local/Cellar/poco/1.4.6/include/ -L/usr/local/Cellar/poco/1.4.6/lib -lPocoFoundation
#SOURCES=rncryptor.cpp rnencryptor.cpp rndecryptor.cpp
SOURCES=src/rncryptor.cpp src/rndecryptor.cpp src/rnencryptor.cpp src/main.cpp src/tests.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=rncryptor

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
