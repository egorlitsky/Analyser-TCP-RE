#include <fstream>
#include <sstream>
#include <thread>
#include <list>
#include <mutex>
#include "StreamCacheStructure.hpp"

#define STREAM_INFO_FILE_NAME      "streamInfo.txt"
#define THREAD_INFO_FILE_NAME      "threadInfo.txt"

extern std::string searchType;
extern int         threadsAmount;
extern int         chunkSize;
extern bool        debugMode;
extern int         fileStreamsAmount;

std::ofstream threadInfoFile(THREAD_INFO_FILE_NAME, std::ios::binary);

std::mutex fileMutex;              // mutex to write Stream info to file correctly
int        fileStreamsCounter = 0; // current number of File streams

StreamCache::StreamCache(std::size_t cacheSize): hits(0), misses(0), collisionsNum(0),
            cache(), maxSize(cacheSize), size(0) {}


float StreamCache::getHitRate(void) const {
    return (float)(hits)/((float)(hits) + misses);
}

int StreamCache::getCollisionsNumber(void) const {
    return collisionsNum;
}

void StreamCache::add(Md5HashedPayload const &hPayload) {
    return;
}

void StreamCache::add(struct in_addr ipSrc, struct in_addr ipDst, 
            u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
            unsigned char * payload, unsigned int payloadSize) {
    
    while (payloadSize + this->size > this->maxSize) {
        StreamCache::cacheIterType streamToRemove = std::min_element(cache.begin(), cache.end());
        int removedStreamSize = streamToRemove->stream.getSize();
        
        if (streamToRemove->stream.isFile) {
            std::string streamFileName = streamToRemove->stream.fileName;
            remove(streamFileName.c_str());
        }
        
        cache.erase(streamToRemove);
        this->size -= removedStreamSize;
    }
    
    bool isFileStream = ((fileStreamsCounter < fileStreamsAmount) && payloadSize) ? true : false;
    TcpStream newStream(ipSrc, ipDst, tcpSport, tcpDport, isFileStream);
    bool isStreamExist = false;
    
    if (isFileStream) {
        ++fileStreamsCounter;
    }
    
    HitData searchResult = this->findPayload(payload, payloadSize);
    
    if (searchResult.dataOffset != -1) {
        ++hits;
        this->cache[searchResult.streamIndex].freq++;
        if (isFileStream) {
            --fileStreamsCounter;
        }
    } else {
        ++misses;
        for (cacheIterType it = cache.begin(); it != cache.end(); ++it) {
            if (it->stream == newStream) {
                isStreamExist = true;
                
                if (isFileStream) {
                    --fileStreamsCounter;
                }
 
                int rc = it->stream.addPacketToStream(tcpSeq, payload, payloadSize);
                if (rc == 0) {
                    this->size += payloadSize;
                }

                break;
            }
        }

        if (!isStreamExist) {
            int rc = newStream.addPacketToStream(tcpSeq, payload, payloadSize);
            if (rc == 0) {
                this->size += payloadSize;
            }
            this->cache.push_back(CacheEntry(0, newStream));
        }
    }
}

void StreamCache::runThread(int threadId, const unsigned char * payload) {
    
    for (int i = 0; i < this->cache.size(); ++i) {
        
        if (this->searchResult.first != -1) {
            return;
        }
        
        if (this->cache[i].stream.isBusy) {
            continue;
        } else {
            this->cache[i].stream.isBusy = true;
        }

        if (debugMode) {
            fileMutex.lock();
            threadInfoFile << "Thread " << threadId << " operates with stream " << i << std::endl;
            fileMutex.unlock();
        }

        std::string streamData = this->cache[i].stream.getStreamData();
        std::size_t streamSize = streamData.length();
        
        int offset = -1;

        if (searchType == SEARCH_CUSTOM_STR_STR) {

            try {
                offset = custom_str_str((unsigned char*) streamData.c_str(), payload, streamSize);
            } catch (...) {
                std::cout << "[ERROR] Exception during runThread() execution";
            }

            if (offset != -1) {
                this->searchResult = std::make_pair(i, offset);
                return;
            }
        }
        
        if (searchType == SEARCH_FIND) {
            std::string packet((char*)payload);
            offset = streamData.find(packet);

            if (offset != std::string::npos) {
                this->searchResult = std::make_pair(i, offset);
                return;
            }
        }

        if (searchType == SEARCH_BOYER_MOORE) {
            std::string packet((char*)payload);
            offset = boyer_moore(streamData, packet);

            if (offset != -1) {
                this->searchResult = std::make_pair(i, offset);
                return;
            }
        }

        if (searchType == SEARCH_KMP) {
            std::string packet((char*)payload);
            offset = knuth_morris_pratt(streamData, packet);

            if (offset != -1) {
                this->searchResult = std::make_pair(i, offset);
                return;
            }
        }
    }
}

StreamCache::HitData StreamCache::findPayload(const unsigned char * payload, const unsigned int payloadSize) {    
    
    if (threadsAmount > 1) {
        this->searchResult = std::make_pair(-1, -1);
        std::vector<std::thread> threads;

        for (int i = 0; i < threadsAmount; ++i) {
            threads.push_back(std::thread(&StreamCache::runThread, this, i, payload));
        }

        if (debugMode) {
            fileMutex.lock();
            threadInfoFile << "========== New packet search ==========" << std::endl << std::endl;
            fileMutex.unlock();
        }

        auto thread = threads.begin();
        while (thread != threads.end()) {
           thread->join();
           thread++;
        }

        for(cacheIterType it = cache.begin(); it != cache.end(); ++it) {
            it->stream.isBusy = false;
        }

        return HitData(this->searchResult.first, this->searchResult.second, payloadSize);

    } else if (!chunkSize) {
        cacheIterType it;
        int streamIndex;

        for(it = cache.begin(), streamIndex = 0; it != cache.end(); ++it, ++streamIndex) {
            std::size_t streamSize = it->stream.streamData.size();
            int offset = -1;

            if (searchType == SEARCH_CUSTOM_STR_STR) {

                try {
                    offset = custom_str_str((unsigned char*) it->stream.streamData.c_str(), payload, streamSize);
                } catch (...) {
                    std::cout << "[ERROR] Exception during findSubstring() execution";
                }

                if (offset != -1) {
                    return HitData(streamIndex, offset, payloadSize);
                }
            }

            if (searchType == SEARCH_FIND) {
                std::string packet((char*)payload);
                offset = it->stream.streamData.find(packet);

                if (offset != std::string::npos) {
                    return HitData(streamIndex, offset, payloadSize);
                }
            }

            if (searchType == SEARCH_BOYER_MOORE) {
                std::string packet((char*)payload);
                offset = boyer_moore(it->stream.streamData, packet);

                if (offset != -1) {
                    return HitData(streamIndex, offset, payloadSize);
                }
            }

            if (searchType == SEARCH_KMP) {
                std::string packet((char*)payload);
                offset = knuth_morris_pratt(it->stream.streamData, packet);

                if (offset != -1) {
                    return HitData(streamIndex, offset, payloadSize);
                }
            }
        }
    } else {
        std::string payload_str = "";
        int offset = 0;
        
        for (int i = 0; i < payloadSize; ++i) {
            payload_str += payload[i];
        }

        while ((offset + chunkSize) < payloadSize) {
            std::string chunk(payload_str.substr(offset, offset + chunkSize));
            Md5HashedPayload *hashedPayload = new Md5HashedPayload((unsigned char *) chunk.c_str(), chunkSize, false);
            
            cacheIterType it;
            int streamIndex;
            
            for(it = cache.begin(), streamIndex = 0; it != cache.end(); ++it, ++streamIndex) {
                if (it->stream.hashedPayloads.count(hashedPayload->getHashKey())) {
                    
                    // TODO: check on collisions
                    return HitData(streamIndex, offset, payloadSize);
                }
            }
            
            ++offset;
        }
        return HitData(-1, -1, 0);
        
    }
    
    return HitData(-1, -1, 0);
}

void StreamCache::printCacheData(void) {
    for(cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        const char *aux       = inet_ntoa(it->stream.ipSrc);
        char       *tempSrcIp = new char[strlen(aux)+1];
        const char *ipSrc     = strcpy(tempSrcIp, aux);

        aux                   = inet_ntoa(it->stream.ipDst);
        char       *tempDstIp = new char[strlen(aux)+1];
        const char *ipDst     = strcpy(tempDstIp, aux);

        std::ostringstream oss;
        oss << "" << ipSrc << "_" << ipDst << "_" << 
                it->stream.tcpSport << "_" << it->stream.tcpDport << ".txt";

        std::string file_name = oss.str();   
        std::ofstream fout(file_name, std::ios::binary);

        // output like the Wireshark output in 'Follow TCP Stream'
        for(auto packet : it->stream.packets) {
            for (int i = 0; i < packet.second.size(); ++i) {

                char c = packet.second[i],
                        wiresharkChar = c >= ' ' && c < 0x7f ? c : '.';

                if (c == '\n' || c == '\r' || c == '\t') {
                    fout << c;
                } else {
                    fout << wiresharkChar;
                }
            }
        }

        fout.close();

        delete[] tempSrcIp;
        delete[] tempDstIp;
    }
}

void StreamCache::printStreamInfo(void) {
    int streamIndex = 0;
    std::ofstream streamInfoFile(STREAM_INFO_FILE_NAME, std::ios::binary);

    for(cacheIterType it = cache.begin(); it != cache.end(); ++it, ++streamIndex) {
        streamInfoFile << "Steam " << streamIndex << " contains "
                << it->stream.packets.size() << " packets, frequency = " 
                << it->freq << std::endl;
    }

    streamInfoFile.close();
}

std::size_t StreamCache::getSize(void) const {
    return size;
}

void StreamCache::clear() {
    cache.clear();
}

StreamCache::~StreamCache() {
    threadInfoFile.close();
    cache.clear();
}