SHELL := /bin/bash

CC=gcc
CFLAGS=-g -Wall
SOURCES=packets.c 
HEADERS=packets.h pcap.h
TEST_SOURCES=test_wfm.c


wfm: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o wfm main.c $(SOURCES) $(HEADERS)
	
clean:
	rm -f *.o wfm AllTests AllTests.c
	
test: $(SOURCES) $(TEST_SOURCES) $(HEADERS)
	
	chmod a+x make-tests.sh
	
	./make-tests.sh > AllTests.c

	$(CC) $(CFLAGS) -o AllTests  AllTests.c CuTest.c $(SOURCES) $(TEST_SOURCES)

	./AllTests
