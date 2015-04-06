#ifndef db_sql_parser_h
#define db_sql_parser_h

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <string>

struct db_sql_parser
{
    int cs;
    size_t nread;
    const char* tok;
    
    db_sql_parser();
    virtual ~db_sql_parser();
    
    virtual void reset();
    size_t execute(const char *buffer, size_t len, bool finish);
    
    std::string dequote(std::string value)
    {
        if (value.length() >= 2 && value[0] == '`' && value[value.length() - 1] == '`') {
            return value.substr(1, value.length() - 2);
        } else {
            return value;
        }
    }

    virtual void statement_begin() = 0;
    virtual void statement_end() = 0;
    virtual void table_begin() = 0;
    virtual void table_schema_name(std::string value) = 0;
    virtual void table_name(std::string value) = 0;
    virtual void table_column_begin() = 0;
    virtual void table_column_name(std::string value) = 0;
    virtual void table_column_type_name(std::string value) = 0;
    virtual void table_column_type_size(std::string value) = 0;
    virtual void table_column_type_decimals(std::string value) = 0;
    virtual void table_column_default_value(std::string value) = 0;
    virtual void table_column_constraint_null() = 0;
    virtual void table_column_constraint_not_null() = 0;
    virtual void table_column_constraint_primary_key() = 0;
    virtual void table_column_constraint_unique() = 0;
    virtual void table_constraint_begin() = 0;
    virtual void table_constraint_name(std::string value) = 0;
    virtual void table_constraint_primary_key() = 0;
    virtual void table_constraint_foreign_key() = 0;
    virtual void table_constraint_unique() = 0;
    virtual void table_constraint_column_name(std::string value) = 0;
    virtual void table_constraint_references_schema_name(std::string value) = 0;
    virtual void table_constraint_references_table_name(std::string value) = 0;
    virtual void table_constraint_references_column_name(std::string value) = 0;
    virtual void table_end() = 0;
    virtual void done() = 0;
};

#endif
