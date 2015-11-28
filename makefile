program_name = SnifferEx
test_name = SnifferTest

CC = g++
LD = g++

CC_FLAGS = -std=c++11

SRC_DIR = src
TEST_DIR = test
BUILD_DIR = bin

MK_BUILD_DIR = mkdir -p ./$(BUILD_DIR)

LIB_DEP = -lpcap -lcrypto
LIB_TEST = -lpthread -lgtest -lgtest_main -L/usr/lib/


all: $(BUILD_DIR)/$(program_name)
	

test: $(BUILD_DIR)/$(test_name)
	

# valgrind_all: all
#	CC_FLAGS = $(CC_FLAGS) -g -ggdb
#	make

# valgrind_test: test
#	CC_FLAGS = $(CC_FLAGS) -g -ggdb
#	make test


$(BUILD_DIR)/$(program_name): $(BUILD_DIR)/main.o $(BUILD_DIR)/NetSniffer.o $(BUILD_DIR)/Md5HashedPayload.o $(BUILD_DIR)/CacheStructure.o
	$(LD) $(CC_FLAGS) $^ $(LIB_DEP) -o $@

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.cpp $(SRC_DIR)/NetSniffer.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/main.cpp -o $@

$(BUILD_DIR)/NetSniffer.o: $(SRC_DIR)/NetSniffer.cpp $(SRC_DIR)/NetSniffer.hpp $(SRC_DIR)/TcpIpInternetHeaders.hpp $(SRC_DIR)/Md5HashedPayload.hpp $(SRC_DIR)/CacheStructure.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/NetSniffer.cpp -o $@

$(BUILD_DIR)/Md5HashedPayload.o: $(SRC_DIR)/Md5HashedPayload.cpp $(SRC_DIR)/Md5HashedPayload.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/Md5HashedPayload.cpp -o $@

$(BUILD_DIR)/CacheStructure.o: $(SRC_DIR)/CacheStructure.cpp $(SRC_DIR)/CacheStructure.hpp $(SRC_DIR)/Md5HashedPayload.hpp
	$(MK_BUILD_DIR)
	$(CC) -$(CC_FLAGS) -c $(SRC_DIR)/CacheStructure.cpp -o $@



$(BUILD_DIR)/$(test_name): $(BUILD_DIR)/UnitTests.o $(BUILD_DIR)/CacheTests.o $(BUILD_DIR)/NetSniffer.o  $(BUILD_DIR)/Md5HashedPayload.o $(BUILD_DIR)/CacheStructure.o
	$(LD) $(CC_FLAGS) $^ $(LIB_DEP) $(LIB_TEST) -o $@

$(BUILD_DIR)/CacheTests.o: $(TEST_DIR)/CacheTests.cpp $(SRC_DIR)/NetSniffer.hpp $(TEST_DIR)/CacheTests.hpp $(SRC_DIR)/Md5HashedPayload.hpp $(SRC_DIR)/CacheStructure.hpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c -I ./ $(TEST_DIR)/CacheTests.cpp -o $@

$(BUILD_DIR)/UnitTests.o: $(TEST_DIR)/UnitTests.cpp
	$(MK_BUILD_DIR)
	$(CC) $(CC_FLAGS) -c -I ./ $(TEST_DIR)/UnitTests.cpp -o $@



clean:
	rm -rfd ./$(BUILD_DIR)

