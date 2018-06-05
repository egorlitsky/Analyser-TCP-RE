# Analyser-TCP-RE-Flow-based-version

This repository forked from Sviftel/Analyser-TCP-RE and extends Packet-RE Analyser to integrate him with TCP-Flow-Cache Analyser.

This repository contains source code of Analyser impementing TCP-Flow-Cache algorythm.

TCP-Flow-Cache allows to cache TCP traffic between two remote nodes. TCP-Flow-Cache approach caches TCP-flows using TCP/IP headers and packet payload. The main idea is caching which doesn't depend of packets / segments fragmentation.

For more details, please, refer the [article](http://www.ndsl.kaist.edu/~kyoungsoo/papers/mobisys13_woo.pdf)

## Install required libraries:

    $ sudo apt-get install libssl-dev
	
    $ sudo apt-get install libtclap-dev
	
    $ sudo apt-get install libpcap-dev

## Make the project:

    $ cd .../Analyser-TCP-RE-Flow-based-version

    $ make -f makefile

## Run with --help option

    $ cd bin

    $ ./SnifferEx --help
