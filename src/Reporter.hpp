#ifndef REPORTER_HPP
#define REPORTER_HPP


class Reporter {
private:
    const int maxBarLength = 50;
    const long long pointStep = 100000;

    int barLength;
    long long packetNumber;
    long long maxPacketNumber;
public:
    Reporter(long long mx);
    void inc();
    void fin();
};

#endif