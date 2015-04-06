//
//  db_sql_model.h
//

#ifndef db_sql_model_h
#define db_sql_model_h

#include <string>
#include <vector>
#include <memory>
#include <sstream>

struct db_sql_statement;
typedef std::shared_ptr<db_sql_statement> db_sql_statement_ptr;
typedef std::vector<db_sql_statement_ptr> db_sql_statement_list;
struct db_column_definition;
typedef std::shared_ptr<db_column_definition> db_column_definition_ptr;
typedef std::vector<db_column_definition_ptr> db_column_definition_list;
struct db_column_constraint;
typedef std::shared_ptr<db_column_constraint> db_column_constraint_ptr;
typedef std::vector<db_column_constraint_ptr> db_column_constraint_list;
struct db_table_constraint;
typedef std::shared_ptr<db_table_constraint> db_table_constraint_ptr;
typedef std::vector<db_table_constraint_ptr> db_table_constraint_list;
struct db_table_definition;
typedef std::shared_ptr<db_table_definition> db_table_definition_ptr;


/* db_sql_statement */

struct db_sql_statement
{
    virtual ~db_sql_statement() {}
    virtual std::string to_string() = 0;
};


/* db_column_constraint */

struct db_column_constraint
{
    enum Type
    {
        Null,
        NotNull,
        Default,
        PrimaryKey,
        Unique,
    };
    
    Type type;
    std::string default_value;
    
    db_column_constraint(Type type) : type(type) {}
    db_column_constraint(Type type, std::string default_value) : type(type), default_value(default_value) {}
    
    std::string to_string();
};


/* db_column_definition */

struct db_column_definition
{
    std::string column_name;
    std::string type_name;
    db_column_constraint_list constraints;
    int size;
    int decimals;
    
    db_column_definition() : size(0), decimals(0) {}
    
    std::string to_string();
};


/* db_table_constraint */

struct db_table_constraint
{
    enum Type
    {
        PrimaryKey,
        ForeignKey,
        Unique,
    };
    
    Type type;
    std::string name;
    std::vector<std::string> columns;
    std::string references_schema_name;
    std::string references_table_name;
    std::vector<std::string> references_columns;
    
    std::string to_string();
};


/* db_table_definition */

struct db_table_definition : db_sql_statement
{
    std::string schema_name;
    std::string table_name;
    db_column_definition_list column_definitions;
    db_table_constraint_list table_constraints;
    
    std::string to_string();
};

#endif
