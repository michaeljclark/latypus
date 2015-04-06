//
//  db_sql_parser_impl.cc
//

#include "db_sql_model.h"
#include "db_sql_parser.h"
#include "db_sql_parser_impl.h"

#include <iostream>


/* db_sql_parser_impl */

bool db_sql_parser_impl::debug = false;

void db_sql_parser_impl::reset()
{
    db_sql_parser::reset();
    statements.clear();
    createTableStatement = db_table_definition_ptr();
}

std::string db_sql_parser_impl::to_string()
{
    std::stringstream ss;
    for (auto statement : statements) {
        ss << statement->to_string() << ";" << std::endl;
    }
    return ss.str();
}

void db_sql_parser_impl::statement_begin()
{
    if (debug) std::cout << __func__ << std::endl;
}

void db_sql_parser_impl::table_begin()
{
    if (debug) std::cout << __func__ << std::endl;
    
    createTableStatement = db_table_definition_ptr(new db_table_definition());
}

void db_sql_parser_impl::table_schema_name(std::string value)
{
    if (debug) std::cout << __func__ << std::endl;
    
    createTableStatement->schema_name = value;
}

void db_sql_parser_impl::table_name(std::string value)
{
    if (debug) std::cout << __func__ << std::endl;
    
    createTableStatement->table_name = value;
}

void db_sql_parser_impl::table_column_begin()
{
    if (debug) std::cout << __func__ << std::endl;
    
    createTableStatement->column_definitions.push_back(db_column_definition_ptr(new db_column_definition()));
}
    
void db_sql_parser_impl::table_column_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->column_name = value;
}

void db_sql_parser_impl::table_column_type_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->type_name = value;
}

void db_sql_parser_impl::table_column_type_size(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->size = atoi(value.c_str());
}

void db_sql_parser_impl::table_column_type_decimals(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->decimals = atoi(value.c_str());
}

void db_sql_parser_impl::table_column_default_value(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;

    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->constraints.push_back(db_column_constraint_ptr(new db_column_constraint(db_column_constraint::Default, value)));
}

void db_sql_parser_impl::table_column_constraint_null()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->constraints.push_back(db_column_constraint_ptr(new db_column_constraint(db_column_constraint::Null)));
}

void db_sql_parser_impl::table_column_constraint_not_null()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->constraints.push_back(db_column_constraint_ptr(new db_column_constraint(db_column_constraint::NotNull)));
}

void db_sql_parser_impl::table_column_constraint_primary_key()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->constraints.push_back(db_column_constraint_ptr(new db_column_constraint(db_column_constraint::PrimaryKey)));
}

void db_sql_parser_impl::table_column_constraint_unique()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_column_definition_ptr column = createTableStatement->column_definitions.back();
    column->constraints.push_back(db_column_constraint_ptr(new db_column_constraint(db_column_constraint::Unique)));
}

void db_sql_parser_impl::table_constraint_begin()
{
    if (debug) std::cout << __func__ << std::endl;
    
    createTableStatement->table_constraints.push_back(db_table_constraint_ptr(new db_table_constraint()));
}

void db_sql_parser_impl::table_constraint_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->name = value;
}

void db_sql_parser_impl::table_constraint_primary_key()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->type = db_table_constraint::PrimaryKey;
}

void db_sql_parser_impl::table_constraint_foreign_key()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->type = db_table_constraint::ForeignKey;
}

void db_sql_parser_impl::table_constraint_unique()
{
    if (debug) std::cout << __func__ << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->type = db_table_constraint::Unique;
}

void db_sql_parser_impl::table_constraint_column_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->columns.push_back(value);
}

void db_sql_parser_impl::table_constraint_references_schema_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->references_schema_name = value;
}

void db_sql_parser_impl::table_constraint_references_table_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->references_table_name = value;
}

void db_sql_parser_impl::table_constraint_references_column_name(std::string value)
{
    if (debug) std::cout << __func__ << ": " << value << std::endl;
    
    db_table_constraint_ptr constraint = createTableStatement->table_constraints.back();
    constraint->references_columns.push_back(value);
}

void db_sql_parser_impl::table_end()
{
    if (debug) std::cout << __func__ << std::endl;
    
    statements.push_back(createTableStatement);
    createTableStatement = db_table_definition_ptr();
}

void db_sql_parser_impl::statement_end()
{
    if (debug) std::cout << __func__ << std::endl;
}

void db_sql_parser_impl::done()
{
    if (debug) std::cout << __func__ << std::endl;
}
