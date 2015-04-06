//
//  test_db_parser.cc
//

#include <string>
#include <iostream>

#include "db_sql_model.h"
#include "db_sql_parser.h"
#include "db_sql_parser_impl.h"

int main(int argc, char **argv)
{
    db_sql_parser_impl sqlparser;
    
    // this has a duplicate primary key but should parse correctly nevertheless
    std::string test1 =
        "CREATE TABLE test ("
        "i int primary key, "
        "j varchar (20, 3) not null unique, "
        "k float null, "
        "o numeric(9), "
        "n numeric(9), "
        "constraint foo primary key (i, j), "
        "constraint bar foreign key (o, n) references foo(o, n)"
        ");\n";
    
    // mysql output from "show create table test" for the following table:
    // create table test (v bigint, s varchar(20), d decimal(10,3));
    std::string test2 =
        "CREATE TABLE `test` ("
        "`v` bigint(20) DEFAULT NULL,"
        "`s` varchar(20) DEFAULT NULL,"
        "`d` decimal(10,3) DEFAULT NULL"
        ") ENGINE=InnoDB DEFAULT CHARSET=latin1\n";
    
    // print input for test1
    std::cout << "INPUT  : " << test1;

    // parse
    sqlparser.reset();
    sqlparser.execute(test1.c_str(), test1.size(), true);
    
    // convert to string and print output
    std::string output1 = sqlparser.to_string();
    std::cout << "OUTPUT : " << output1;
    
    // reparse output
    sqlparser.reset();
    sqlparser.execute(output1.c_str(), output1.size(), true);
    
    // convert to string and print reparsed output
    std::string output2 = sqlparser.to_string();
    std::cout << "REPARSE: " << output2;
    
    if (output1 == output2) {
        std::cout << "reparse output matches: SUCCESS" << std::endl;
    } else {
        std::cout << "reparse output does not match: FAILED" << std::endl;
    }
    
    // print input for test2
    std::cout << "INPUT  : " << test2;
    
    // parse
    sqlparser.reset();
    sqlparser.execute(test2.c_str(), test2.size(), true);
    
    // convert to string and print output
    output1 = sqlparser.to_string();
    std::cout << "OUTPUT : " << output1;
    
    // reparse output
    sqlparser.reset();
    sqlparser.execute(output1.c_str(), output1.size(), true);
    
    // convert to string and print reparsed output
    output2 = sqlparser.to_string();
    std::cout << "REPARSE: " << output2;
    
    if (output1 == output2) {
        std::cout << "reparse output matches: SUCCESS" << std::endl;
    } else {
        std::cout << "reparse output does not match: FAILED" << std::endl;
    }

    return 0;
}
