program_name = SnifferEx
test_name = SnifferTest

CC = g++
LD = g++

CC_FLAGS = -std=c++11 -g -ggdb
LD_FLAGS = -g -ggdb

SRC_DIR = src
TEST_DIR = test
BUILD_DIR = bin

MK_BUILD_DIR = mkdir -p ./$(BUILD_DIR)

OBJS_NSF = $(BUILD_DIR)/NetSniffer.o $(BUILD_DIR)/Md5HashedPayload.o $(BUILD_DIR)/TcpStream.o $(BUILD_DIR)/CacheStructure.o $(BUILD_DIR)/StreamCacheStructure.o $(BUILD_DIR)/Reporter.o
OBJS_MAIN = $(BUILD_DIR)/main.o $(OBJS_NSF)
OBJS_TEST = $(BUILD_DIR)/UnitTests.o $(BUILD_DIR)/CacheTests.o $(OBJS_NSF)

LIB_DEP = -lpcap -lcrypto
LIB_TEST = -lpthread -lgtest -lgtest_main -L/usr/lib/


all: $(BUILD_DIR)/$(program_name)


test: $(BUILD_DIR)/$(test_name)


release:
	make
	strip -g $(BUILD_DIR)/$(program_name)

$(BUILD_DIR)/$(program_name): $(OBJS_MAIN)
	$(LD) $(LD_FLAGS) $^ $(LIB_DEP) -o $@

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.cpp $(SRC_DIR)/NetSniffer.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/main.cpp -o $@

$(BUILD_DIR)/Reporter.o: $(SRC_DIR)/Reporter.cpp $(SRC_DIR)/Reporter.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/Reporter.cpp -o $@

$(BUILD_DIR)/Md5HashedPayload.o: $(SRC_DIR)/Md5HashedPayload.cpp $(SRC_DIR)/Md5HashedPayload.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/Md5HashedPayload.cpp -o $@

$(SRC_DIR)/TcpStream.hpp: $(SRC_DIR)/Md5HashedPayload.hpp

$(BUILD_DIR)/TcpStream.o: $(SRC_DIR)/TcpStream.cpp $(SRC_DIR)/TcpStream.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/TcpStream.cpp -o $@

$(SRC_DIR)/ICache.hpp: $(SRC_DIR)/Md5HashedPayload.hpp

$(SRC_DIR)/CacheStructure.hpp: $(SRC_DIR)/Md5HashedPayload.hpp $(SRC_DIR)/ICache.hpp
$(BUILD_DIR)/CacheStructure.o: $(SRC_DIR)/CacheStructure.cpp $(SRC_DIR)/CacheStructure.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/CacheStructure.cpp -o $@
	
$(SRC_DIR)/StreamCacheStructure.hpp: $(SRC_DIR)/TcpStream.hpp

$(BUILD_DIR)/StreamCacheStructure.o: $(SRC_DIR)/StreamCacheStructure.cpp $(SRC_DIR)/StreamCacheStructure.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/StreamCacheStructure.cpp -o $@

$(SRC_DIR)/NetSniffer.hpp: $(SRC_DIR)/CacheStructure.hpp $(SRC_DIR)/Reporter.hpp

$(SRC_DIR)/NetSniffer.cpp: $(SRC_DIR)/TcpIpInternetHeaders.hpp

$(BUILD_DIR)/NetSniffer.o: $(SRC_DIR)/NetSniffer.cpp $(SRC_DIR)/NetSniffer.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/NetSniffer.cpp -o $@

$(BUILD_DIR)/$(test_name): $(OBJS_TEST)
	$(LD) $(LD_FLAGS) $^ $(LIB_DEP) $(LIB_TEST) -o $@

$(TEST_DIR)/CacheTests.hpp: $(SRC_DIR)/NetSniffer.hpp


$(BUILD_DIR)/CacheTests.o: $(TEST_DIR)/CacheTests.cpp $(TEST_DIR)/CacheTests.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c -I ./ $(TEST_DIR)/CacheTests.cpp -o $@

$(BUILD_DIR)/UnitTests.o: $(TEST_DIR)/UnitTests.cpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c -I ./ $(TEST_DIR)/UnitTests.cpp -o $@


clean:
	rm -rfd ./$(BUILD_DIR)

