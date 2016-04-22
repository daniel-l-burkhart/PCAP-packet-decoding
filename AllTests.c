

/* This is auto-generated code. Edit at your own peril. */
#include <stdio.h>
#include <stdlib.h>

#include "CuTest.h"


extern void Test_src_tcp_port(CuTest*);
extern void Test_dest_tcp_port(CuTest*);
extern void Test_src_ip_address(CuTest*);
extern void Test_dest_ip_address(CuTest*);
extern void Test_src_mac_address(CuTest*);
extern void Test_dest_mac_address(CuTest*);


void RunAllTests(void) 
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();


    SUITE_ADD_TEST(suite, Test_src_tcp_port);
    SUITE_ADD_TEST(suite, Test_dest_tcp_port);
    SUITE_ADD_TEST(suite, Test_src_ip_address);
    SUITE_ADD_TEST(suite, Test_dest_ip_address);
    SUITE_ADD_TEST(suite, Test_src_mac_address);
    SUITE_ADD_TEST(suite, Test_dest_mac_address);

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);
    CuStringDelete(output);
    CuSuiteDelete(suite);
}

int main(void)
{
    RunAllTests();
	return EXIT_SUCCESS;
}

