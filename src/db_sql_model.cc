//
//  db_sql_model.cc
//

#include "db_sql_model.h"


/* db_column_constraint */

std::string db_column_constraint::to_string()
{
    switch (type) {
        case Null:          return "NULL";
        case NotNull:       return "NOT NULL";
        case Default:       return "DEFAULT " + default_value;
        case PrimaryKey:    return "PRIMARY KEY";
        case Unique:        return "UNIQUE";
    }
}


/* db_column_definition */

std::string db_column_definition::to_string()
{
    std::stringstream ss;
    ss << column_name << " " << type_name;
    if (size > 0) {
        ss << "(" << size;
        if (decimals > 0) {
            ss << "," << decimals;
        }
        ss << ")";
    }
    for (auto constraint : constraints) {
        ss << " " << constraint->to_string();
    }
    return ss.str();
}


/* db_table_definition */

std::string db_table_definition::to_string()
{
    std::stringstream ss;
    ss << "CREATE TABLE ";
    if (schema_name.length() > 0) {
        ss << schema_name << ".";
    }
    ss << table_name << " (";
    for (auto di = column_definitions.begin(); di != column_definitions.end(); di++) {
        if ((*di)->column_name.length() == 0) continue; // BUG in grammar - spurious table_column_begin event
        if (di != column_definitions.begin()) ss << ", ";
        ss << (*di)->to_string();
    }
    for (auto ci = table_constraints.begin(); ci != table_constraints.end(); ci++) {
        ss << ", " << (*ci)->to_string();
    }
    ss << ")";
    return ss.str();
}


/* db_table_constraint */

std::string db_table_constraint::to_string()
{
    std::stringstream ss;
    if (name.length() > 0) {
        ss << "CONSTRAINT " << name << " ";
    }
    switch (type) {
        case PrimaryKey:
            ss << "PRIMARY KEY (";
            for (auto ci = columns.begin(); ci != columns.end(); ci++) {
                if (ci != columns.begin()) ss << ", ";
                ss << *ci;
            }
            ss << ")";
            break;
        case ForeignKey:
            ss << "FOREIGN KEY (";
            for (auto ci = columns.begin(); ci != columns.end(); ci++) {
                if (ci != columns.begin()) ss << ", ";
                ss << *ci;
            }
            ss << ") REFERENCES ";
            if (references_schema_name.length() > 0) {
                ss << references_schema_name << ".";
            }
            ss << references_table_name << "(";
            for (auto ci = references_columns.begin(); ci != references_columns.end(); ci++) {
                if (ci != references_columns.begin()) ss << ", ";
                ss << *ci;
            }
            ss << ")";
            break;
        case Unique:
            ss << "UNIQUE (";
            for (auto ci = columns.begin(); ci != columns.end(); ci++) {
                if (ci != columns.begin()) ss << ", ";
                ss << *ci;
            }
            ss << ")";
            break;
    }
    return ss.str();
}

