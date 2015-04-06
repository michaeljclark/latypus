//
//  db_sql_parser_impl.h
//

#ifndef db_sql_parser_impl_h
#define db_sql_parser_impl_h

#include <string>
#include <vector>
#include <memory>
#include <sstream>


/* db_sql_parser_impl */

struct db_sql_parser_impl : db_sql_parser
{
    static bool debug;
    
    db_sql_statement_list statements;
    db_table_definition_ptr createTableStatement;

    void reset();
    std::string to_string();

    void statement_begin();
    void table_begin();
    void table_schema_name(std::string value);
    void table_name(std::string value);
    void table_column_begin();
    void table_column_name(std::string value);
    void table_column_type_name(std::string value);
    void table_column_type_size(std::string value);
    void table_column_type_decimals(std::string value);
    void table_column_default_value(std::string value);
    void table_column_constraint_null();
    void table_column_constraint_not_null();
    void table_column_constraint_primary_key();
    void table_column_constraint_unique();
    void table_constraint_begin();
    void table_constraint_name(std::string value);
    void table_constraint_primary_key();
    void table_constraint_foreign_key();
    void table_constraint_unique();
    void table_constraint_column_name(std::string value);
    void table_constraint_references_schema_name(std::string value);
    void table_constraint_references_table_name(std::string value);
    void table_constraint_references_column_name(std::string value);
    void table_end();
    void statement_end();
    void done();
};

#endif