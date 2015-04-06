//
//  test_db.cc
//

#include <stdio.h>
#include <stdlib.h>

#include "db.h"
#include "db_mysql.h"
#include "db_sqlite3.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestCaller.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>


/*
 * db Database tests
 *
 * MySQL tests require MySQL running on localhost with this config:
 *
 * CREATE DATABASE test;
 * CREATE USER 'scott'@'localhost' IDENTIFIED BY 'tiger';
 * GRANT ALL PRIVILEGES ON test.* to 'scott'@'localhost';
 */


/*
 * db_test - specifies test database connection
 */

struct db_test
{
    std::string uri, user, pass;
    
    db_test(std::string uri = "", std::string user = "", std::string pass = "")
        : uri(uri), user(user), pass(pass) {}
};

static db_test testdb;


/*
 * db_test_fixture - test case definitions
 */

class db_test_fixture : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(db_test_fixture);
    CPPUNIT_TEST(testConnectInvalidURI);
    CPPUNIT_TEST(testConnectException);
    CPPUNIT_TEST(testRowsChanged);
    CPPUNIT_TEST(testSelectData);
    CPPUNIT_TEST(testSelectDataWithBind);
    CPPUNIT_TEST(testAutoCommitOffCommit);
    CPPUNIT_TEST(testAutoCommitOffRollback);
    CPPUNIT_TEST(testTableMetaData);
    CPPUNIT_TEST(testQueryMetaData);
    CPPUNIT_TEST(testPrintMetaData);
    CPPUNIT_TEST_SUITE_END();

public:
    
    void setUp() {}
    void tearDown() {}
    
    void testConnectInvalidURI()
    {
        db_exception_code exception_code = db_exception_code_none;
        try {
            db_connection_ptr conn = db::openConnection("foo://");
        } catch (db_exception &e) {
            exception_code = db_exception_code_invalid_uRI;
        }
        CPPUNIT_ASSERT(exception_code == db_exception_code_invalid_uRI);
    }
    
    void testConnectException()
    {
        db_exception_code exception_code = db_exception_code_none;
        try {
            db_connection_ptr conn = db::openConnection(testdb.uri + "/xxx/xxx/", testdb.user, testdb.pass);
        } catch (db_exception &e) {
            exception_code = db_exception_code_connect_failed;
        }
        CPPUNIT_ASSERT(exception_code == db_exception_code_connect_failed);
    }

    void testRowsChanged()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        db_statement_ptr stmt = conn->prepareStatement("insert into test values (1, 'hello', 4.5);");
        stmt->execute();
        CPPUNIT_ASSERT(stmt->getRowsChanged() == 1);
    }

    void testSelectData()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        conn->prepareStatement("insert into test values (1, 'hello', 4.5);")->execute();
        conn->prepareStatement("insert into test values (2, 'bonjour', 5.6);")->execute();
        db_statement_ptr stmt = conn->prepareStatement("select * from test;");
        db_result_set_ptr results = stmt->execute();
        CPPUNIT_ASSERT(results->next() == true);
        CPPUNIT_ASSERT(results->getInt(0) == 1);
        CPPUNIT_ASSERT(results->getString(1) == "hello");
        CPPUNIT_ASSERT(results->getDouble(2) == 4.5);
        CPPUNIT_ASSERT(results->next() == true);
        CPPUNIT_ASSERT(results->getInt(0) == 2);
        CPPUNIT_ASSERT(results->getString(1) == "bonjour");
        CPPUNIT_ASSERT(results->getDouble(2) == 5.6);
        CPPUNIT_ASSERT(results->next() == false);
    }
    
    void testSelectDataWithBind()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        conn->prepareStatement("insert into test values (1, 'hello', 4.5);")->execute();
        conn->prepareStatement("insert into test values (2, 'bonjour', 5.6);")->execute();
        db_statement_ptr stmt = conn->prepareStatement("select * from test where v > ?;");
        CPPUNIT_ASSERT(stmt->getParamCount() == 1);
        CPPUNIT_ASSERT(stmt->getFieldCount() == 3);
        stmt->setInt(0, 1);
        db_result_set_ptr results = stmt->execute();
        CPPUNIT_ASSERT(results->next() == true);
        CPPUNIT_ASSERT(results->getInt(0) == 2);
        CPPUNIT_ASSERT(results->getString(1) == "bonjour");
        CPPUNIT_ASSERT(results->getDouble(2) == 5.6);
        CPPUNIT_ASSERT(results->next() == false);
    }

    void testAutoCommitOffCommit()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        conn->setAutoCommit(false);
        conn->prepareStatement("insert into test values (1, 'hello', 4.5);")->execute();
        conn->prepareStatement("insert into test values (2, 'bonjour', 5.6);")->execute();
        conn->commit();
        db_statement_ptr stmt = conn->prepareStatement("select count(*) from test;");
        CPPUNIT_ASSERT(stmt->getParamCount() == 0);
        CPPUNIT_ASSERT(stmt->getFieldCount() == 1);
        db_result_set_ptr results = stmt->execute();
        CPPUNIT_ASSERT(results->next() == true);
        CPPUNIT_ASSERT(results->getInt(0) == 2);
    }
    
    void testAutoCommitOffRollback()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        conn->setAutoCommit(false);
        conn->prepareStatement("insert into test values (1, 'hello', 4.5);")->execute();
        conn->prepareStatement("insert into test values (2, 'bonjour', 5.6);")->execute();
        conn->rollback();
        db_statement_ptr stmt = conn->prepareStatement("select count(*) from test;");
        CPPUNIT_ASSERT(stmt->getParamCount() == 0);
        CPPUNIT_ASSERT(stmt->getFieldCount() == 1);
        db_result_set_ptr results = stmt->execute();
        CPPUNIT_ASSERT(results->next() == true);
        CPPUNIT_ASSERT(results->getInt(0) == 0);
    }

    void testTableMetaData()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        db_metadata_ptr metadata = conn->getMetaData();
        db_table_definition_ptr table_def = metadata->getTableDefinition("test");
        CPPUNIT_ASSERT(table_def != db_table_definition_ptr());
        CPPUNIT_ASSERT(table_def->table_name == "test");
        CPPUNIT_ASSERT(table_def->column_definitions[0]->column_name == "v");
        CPPUNIT_ASSERT(table_def->column_definitions[1]->column_name == "s");
        CPPUNIT_ASSERT(table_def->column_definitions[2]->column_name == "d");
        CPPUNIT_ASSERT(table_def->column_definitions[0]->type_name == "bigint");
        CPPUNIT_ASSERT(table_def->column_definitions[1]->type_name == "varchar");
        CPPUNIT_ASSERT(table_def->column_definitions[2]->type_name == "decimal");
    }
    
    void testQueryMetaData()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (v bigint, s varchar(20), d decimal(10,3));")->execute();
        db_statement_ptr stmt = conn->prepareStatement("select * from test;");
        db_result_set_ptr results = stmt->execute();
        CPPUNIT_ASSERT(stmt->getParamCount() == 0);
        CPPUNIT_ASSERT(stmt->getFieldCount() == 3);
        const db_field_metadata *meta0 = &stmt->getFieldMetaData(0);
        const db_field_metadata *meta1 = &stmt->getFieldMetaData(1);
        const db_field_metadata *meta2 = &stmt->getFieldMetaData(2);
        CPPUNIT_ASSERT(meta0->column_name == "v");
        CPPUNIT_ASSERT(meta1->column_name == "s");
        CPPUNIT_ASSERT(meta2->column_name == "d");
    }

    void testPrintMetaData()
    {
        db_connection_ptr conn = db::openConnection(testdb.uri, testdb.user, testdb.pass);
        try { conn->prepareStatement("drop table test;")->execute(); } catch (db_exception &e) {}
        conn->prepareStatement("create table test (t tinyint, s smallint, i int, b bigint, v varchar(32), "
                               "f float, lf double, n numeric(9), d decimal(10,3), ts timestamp);")->execute();
        conn->prepareStatement("insert into test values (1, 1, 1, 1, 'hello', 1.0, 1.0, 1.0, 1.0, '2013-11-03 10:07:34');")->execute();
        db_statement_ptr stmt = conn->prepareStatement("select * from test;"); // note sqlite types are not discovered if table is empty
        db_result_set_ptr results = stmt->execute();
        printf("\n");
        for (int i = 0; i < stmt->getFieldCount(); i++) {
            const db_field_metadata *meta = &stmt->getFieldMetaData(i);
            printf("Field %u name=%-16s table=%-16s db=%-10s field_type=%-10s sql_type=%-10s length=%-5lu decimals=%-3d flags=%s\n",
                   (unsigned int)i, meta->column_name.c_str(), meta->table_name.c_str(), meta->db_name.c_str(),
                   db_field_metadata::type_to_string(meta->field_type).c_str(), db_field_metadata::type_to_string(meta->sql_type).c_str(),
                   meta->length, meta->decimals, db_field_metadata::flags_to_string(meta->flags).c_str());
        }
    }
};


/*
 * run suites
 */

int main(int argc, char **argv)
{
    db::registerDriver(&db_driver_mysql::driver);
    db::registerDriver(&db_driver_sqlite3::driver);
    
    // setup test runner
    CppUnit::TextUi::TestRunner runner;
    runner.addTest(db_test_fixture::suite());
    
    // run tests with mysql
    testdb = db_test("mysql://localhost/test", "scott", "tiger");
    fprintf(stderr, "running tests with %s\n", testdb.uri.c_str());
    runner.run();

    // run tests with sqlite3
    testdb = db_test("sqlite3://test.db");
    fprintf(stderr, "running tests with %s\n", testdb.uri.c_str());
    runner.run();

    return 0;
}
