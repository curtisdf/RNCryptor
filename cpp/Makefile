
CC=g++
CFLAGS=-c -Wall

CRYPTOPP_DIR=/usr/local/Cellar/cryptopp/5.6.1
POCO_DIR=/usr/local/Cellar/poco/1.4.6

SHARED_LIB_LDFLAGS=-I$(CRYPTOPP_DIR)/include -L$(CRYPTOPP_DIR)/lib -lcryptopp
SHARED_LIB_SOURCES=src/base.cpp src/encrypt.cpp src/decrypt.cpp
SHARED_LIB_OBJECTS=$(SHARED_LIB_SOURCES:.cpp=.o)
SHARED_LIB_EXECUTABLE=librncryptor.dylib

MAIN_LDFLAGS=-L. -lrncryptor  -I$(POCO_DIR)/include/ -L$(POCO_DIR)/lib -lPocoFoundation -lPocoUtil
MAIN_SOURCES=src/app.cpp
MAIN_OBJECTS=$(MAIN_SOURCES:.cpp=.o)
MAIN_EXECUTABLE=rncryptor

TEST_LDFLAGS=-L. -lrncryptor
TEST_SOURCES=src/tests.cpp src/rncryptortest.cpp
TEST_OBJECTS=$(TEST_SOURCES:.cpp=.o)
TEST_EXECUTABLE=rncryptortest

EXECUTABLES=$(SHARED_LIB_EXECUTABLE) $(MAIN_EXECUTABLE) $(TEST_EXECUTABLE)
OBJECTS_DIR=src

all: $(SHARED_LIB_EXECUTABLE) $(MAIN_EXECUTABLE) $(TEST_EXECUTABLE)

$(SHARED_LIB_EXECUTABLE): $(SHARED_LIB_OBJECTS)
	$(CC) -dynamiclib $(SHARED_LIB_LDFLAGS) $(SHARED_LIB_OBJECTS) -o $@

$(MAIN_EXECUTABLE): $(SHARED_LIB) $(MAIN_OBJECTS)
	$(CC) $(MAIN_LDFLAGS) $(MAIN_OBJECTS) -o $@

$(TEST_EXECUTABLE): $(SHARED_LIB) $(TEST_OBJECTS)
	$(CC) $(TEST_LDFLAGS) $(TEST_OBJECTS) -o $@


.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(EXECUTABLES) $(OBJECTS_DIR)/*.o


#$(CXX) -fPIC -c shared.cpp -o shared.o
#    $(CXX) -shared  -Wl,-soname,libshared.so -o libshared.so shared.o
