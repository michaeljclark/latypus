#include "db_sql_parser.h"

#define TOKEN std::string(tok, p - tok)

%%{
    
    machine db_sql_parser;
    
    CREATE = /CREATE/i;
    DROP = /DROP/i;
    TEMP = /TEMP/i;
    TEMPORARY = /TEMPORARY/i;
    TABLE = /TABLE/i;
    DEFAULT = /DEFAULT/i;
    NULL = /NULL/i;
    NOT = /NOT/i;
    FOREIGN = /FOREIGN/i;
    PRIMARY = /PRIMARY/i;
    KEY = /KEY/i;
    CONSTRAINT = /CONSTRAINT/i;
    UNIQUE = /UNIQUE/i;
    REFERENCES = /REFERENCES/i;
    
    ws = ( ' ' | '\t' | '\n' );
    
    NOT_NULL = ( NOT ws+ NULL );
    PRIMARY_KEY = ( PRIMARY ws+ KEY );
    FOREIGN_KEY = ( FOREIGN ws+ KEY );

    reserved = (CREATE | DROP | TEMP | TEMPORARY | TABLE | DEFAULT | NULL | NULL | PRIMARY | FOREIGN | KEY | CONSTRAINT | UNIQUE | REFERENCES );
    
    action token_start { tok = fpc; }
    
    Identifier =                            ( ( alpha [0-9a-zA-Z_]* | '`' (any* -- '`' ) '`') -- reserved );
    Value =                                 ( '\'' (any* -- '\'' ) '\'' );
    Digits =                                ( [0-9]+ );
    
    TableSchemaName =                       Identifier >token_start %{ table_schema_name(dequote(TOKEN)); };
    TableName =                             ( TableSchemaName '.' )? Identifier >token_start %{ table_name(dequote(TOKEN)); };
    TableColumnDataTypeName =               Identifier >token_start %{ table_column_type_name(TOKEN); };
    TableColumnDataTypeQualifierSize =      Digits >token_start %{ table_column_type_size(TOKEN); };
    TableColumnDataTypeQualifierDecimals =  Digits >token_start %{ table_column_type_decimals(TOKEN); };
    TableColumnDataTypeQualifier =          ( TableColumnDataTypeQualifierSize ( ws* ',' ws* TableColumnDataTypeQualifierDecimals )? );
    TableColumnDataType =                   ( TableColumnDataTypeName ( ws* '(' ws* TableColumnDataTypeQualifier ws* ')' ws* )? );
    TableColumnName =                       Identifier >token_start %{ table_column_name(dequote(TOKEN)); };
    
    TableColumnDefaultValue =               ( Value | NULL ) >token_start %{ table_column_default_value(TOKEN); };
    TableColumnConstraintDefault =          ( DEFAULT ws+ TableColumnDefaultValue );
    TableColumnConstraintNull =             ( NULL ) %{ table_column_constraint_null(); };
    TableColumnConstraintNotNull =          ( NOT_NULL ) %{ table_column_constraint_not_null(); };
    TableColumnConstraintPrimaryKey =       ( PRIMARY_KEY ) %{ table_column_constraint_primary_key(); };
    TableColumnConstraintUnique =           ( UNIQUE ) %{ table_column_constraint_unique(); };
    TableColumnConstraints =                ( TableColumnConstraintNotNull | TableColumnConstraintNull | TableColumnConstraintPrimaryKey
                                            | TableColumnConstraintUnique | TableColumnConstraintDefault );
    TableColumnDefinition =                 ( TableColumnName ws+ TableColumnDataType ( ws+ TableColumnConstraints )* );
    
    TableConstraintReferencesSchemaName =   Identifier >token_start %{ table_constraint_references_schema_name(dequote(TOKEN)); };
    TableConstraintReferencesTableName =    ( TableConstraintReferencesSchemaName '.' )? Identifier
                                            >token_start %{ table_constraint_references_table_name(dequote(TOKEN)); };
    TableConstraintReferencesColumnName =   Identifier >token_start %{ table_constraint_references_column_name(dequote(TOKEN)); };
    TableConstraintReferencesDefinition =   ( REFERENCES ws+ TableConstraintReferencesTableName ws*
                                            '(' ws* TableConstraintReferencesColumnName
                                            ( ws* ',' ws* TableConstraintReferencesColumnName )* ws* ')' );
    TableConstraintColumnName =             Identifier >token_start %{ table_constraint_column_name(dequote(TOKEN)); };
    TableConstraintForeignKey =             ( FOREIGN_KEY ws* '(' ws* TableConstraintColumnName
                                            ( ws* ',' ws* TableConstraintColumnName )* ws* ')' ws* TableConstraintReferencesDefinition )
                                            >{ table_constraint_foreign_key(); };
    TableConstraintPrimaryKey =             ( PRIMARY_KEY ws* '(' ws* TableConstraintColumnName
                                            ( ws* ',' ws* TableConstraintColumnName )* ws* ')' )
                                            >{ table_constraint_primary_key(); };
    TableConstraintUnique =                 ( UNIQUE ws* '(' ws* TableConstraintColumnName
                                            ( ws* ',' ws* TableConstraintColumnName )* ws* ')' )
                                            >{ table_constraint_unique(); };
    TableConstraints =                      ( TableConstraintPrimaryKey | TableConstraintUnique | TableConstraintForeignKey );
    TableConstraintName =                   Identifier  >token_start %{ table_constraint_name(dequote(TOKEN)); };
    TableConstraint =                       ( ( CONSTRAINT ws+ TableConstraintName ws+)? TableConstraints ) >{ table_constraint_begin(); };
    
    TableElement =                          TableColumnDefinition >{ table_column_begin(); };
    TableElementList =                      ( '(' ws* TableElement ( ws* ',' ws* TableElement )* ( ws* ',' ws* TableConstraint )* ws* ')' );
    
    CreateTableStatement =                  ( CREATE ws+ ( ( TEMP | TEMPORARY ) ws+ )? TABLE ws+ TableName ws* TableElementList )
                                            >{ table_begin(); } %{ table_end(); };
    
    SchemaDefinitionStatement =             ( CreateTableStatement );
    Statement =                             ( SchemaDefinitionStatement ) >{ statement_begin(); } %{ statement_end(); };
    
    SQL =                                   ( ws* Statement ws* (';' ws* Statement ws* )* ';'? ) %{ done(); fbreak; };
    
    main := SQL;
    
}%%

%% write data;

db_sql_parser::db_sql_parser() { reset(); }
db_sql_parser::~db_sql_parser() {}

void db_sql_parser::reset()
{
    %% write init;
    
    nread = 0;
    tok = 0;
}

size_t db_sql_parser::execute(const char *buffer, size_t len, bool finish)
{
    const char *p = buffer;
    const char *pe = buffer + len;
    const char *eof = finish ? pe : NULL;
    
    %% write exec;
    
    nread += p - buffer;
    
    return nread;
}
