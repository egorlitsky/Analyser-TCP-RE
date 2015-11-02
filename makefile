CC = g++
LD = g++

SRC_DIR = src
TEST_DIR = test
BUILD_DIR = bin

program_name = SniferEx
test_name = SnifferTest
LIB_DEP = -lpcap -lcrypto
LIB_TEST = -lpthread -lgtest -lgtest_main -L/usr/lib/


all: $(BUILD_DIR)/$(program_name)
	

test: $(BUILD_DIR)/$(test_name)
	

$(BUILD_DIR)/$(program_name): $(BUILD_DIR)/main.o $(BUILD_DIR)/NetSniffer.o $(BUILD_DIR)/Md5HashedPayload.o $(BUILD_DIR)/CacheStructure.o
	$(LD) -std=c++11 $^ $(LIB_DEP) -o $@

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.cpp $(SRC_DIR)/NetSniffer.hpp
	$(CC) -std=c++11 -c $(SRC_DIR)/main.cpp -o $@

$(BUILD_DIR)/NetSniffer.o: $(SRC_DIR)/NetSniffer.cpp $(SRC_DIR)/NetSniffer.hpp $(SRC_DIR)/TcpIpInternetHeaders.hpp $(SRC_DIR)/Md5HashedPayload.hpp $(SRC_DIR)/CacheStructure.hpp
	$(CC) -std=c++11 -c $(SRC_DIR)/NetSniffer.cpp -o $@

$(BUILD_DIR)/Md5HashedPayload.o: $(SRC_DIR)/Md5HashedPayload.cpp $(SRC_DIR)/Md5HashedPayload.hpp
	$(CC) -std=c++11 -c $(SRC_DIR)/Md5HashedPayload.cpp -o $@

$(BUILD_DIR)/CacheStructure.o: $(SRC_DIR)/CacheStructure.cpp $(SRC_DIR)/CacheStructure.hpp $(SRC_DIR)/Md5HashedPayload.hpp
	$(CC) -std=c++11 -c $(SRC_DIR)/CacheStructure.cpp -o $@



$(BUILD_DIR)/$(test_name): $(BUILD_DIR)/UnitTests.o $(BUILD_DIR)/NetSniffer.o $(BUILD_DIR)/Md5HashedPayload.o $(BUILD_DIR)/CacheStructure.o
	$(LD) -std=c++11 $^ $(LIB_DEP) $(LIB_TEST) -o $@

$(BUILD_DIR)/UnitTests.o: $(TEST_DIR)/UnitTests.cpp $(SRC_DIR)/NetSniffer.hpp $(SRC_DIR)/TcpIpInternetHeaders.hpp $(SRC_DIR)/Md5HashedPayload.hpp $(SRC_DIR)/CacheStructure.hpp
	$(CC) -std=c++11 -c -I ./$(SRC_DIR) $(TEST_DIR)/UnitTests.cpp -o $@



clean:
	rm -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(program_name) $(BUILD_DIR)/$(test_name)
