//
//  db.h
//

#ifndef db_h
#define db_h

#include "db_sql_model.h"

#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <memory>

class db_driver;
typedef std::map<std::string,db_driver*> db_driver_map;
class db_connection_uri;
typedef std::shared_ptr<db_connection_uri> db_connection_uri_ptr;
class db_metadata;
typedef std::shared_ptr<db_metadata> db_metadata_ptr;
class db_connection;
typedef std::shared_ptr<db_connection> db_connection_ptr;
class db_statement;
typedef std::shared_ptr<db_statement> db_statement_ptr;
class db_result_set;
typedef std::shared_ptr<db_result_set> db_result_set_ptr;
class db_field_metadata;
typedef std::vector<db_field_metadata> db_field_metadata_list;
class db_exception;


/* db_exception_code */

enum db_exception_code {
    db_exception_code_none,
    db_exception_code_invalid_uRI,
    db_exception_code_connect_failed,
    db_exception_code_prepare_failed,
    db_exception_code_execute_failed,
    db_exception_code_set_auto_commit_failed,
    db_exception_code_commit_failed,
    db_exception_code_rollback_failed,
    db_exception_code_cursor_error,
    db_exception_code_metadata_error,
    db_exception_code_unimplemented,
};

/* db_exception */

std::string format_string(const char* fmt, ...);

class db_exception : public std::exception {
private:
    db_exception_code code;
    std::string message;
    std::string _what;
    
public:
    db_exception(db_exception_code code, std::string message);
    
    db_exception_code getCode();
    std::string getMessage();
    
    virtual const char* what();
};


/* db */

class db {
private:
    static db_driver_map drivers;
    
public:
    static void registerDriver(db_driver *driver);
    static db_connection_ptr openConnection(std::string db_uri, std::string username = "", std::string password = "") throw(db_exception);
};


/* db_driver */

class db_driver
{
public:
    virtual ~db_driver();
    
    virtual std::vector<std::string> getDriverNames() = 0;
    virtual db_connection_ptr createConnection(const std::string &db_uri, const std::string &username, const std::string &password) = 0;
};


/* db_connection_uri */

class db_connection_uri
{
public:
    std::string db_uri;
    std::string username;
    std::string password;
    
    db_connection_uri(const std::string &db_uri, const std::string &username, const std::string &password);
    virtual ~db_connection_uri();
    
    virtual void decode() throw(db_exception) = 0;
    virtual std::string to_string() const = 0;
};


/* db_metadata */

class db_metadata {
public:
    virtual ~db_metadata();
    
    virtual std::vector<std::string> getTableNames(std::string schema_name = "") = 0;
    virtual db_table_definition_ptr getTableDefinition(std::string table_name, std::string schema_name = "") = 0;
};


/* db_connection */

class db_connection {
public:
    db_connection_uri_ptr conn_uri;
    
    db_connection(db_connection_uri_ptr conn_uri);
    virtual ~db_connection();
    
    db_connection_uri_ptr getUri() { return conn_uri; }
    
    virtual void connect() throw(db_exception) = 0;
    virtual bool getAutoCommit() throw(db_exception) = 0;
    virtual void setAutoCommit(bool autocommit) throw(db_exception) = 0;
    virtual void commit() throw(db_exception) = 0;
    virtual void rollback() throw(db_exception) = 0;
    virtual db_metadata_ptr getMetaData() = 0;
    virtual db_statement_ptr prepareStatement(std::string sql) throw(db_exception) = 0;
};


/* db_statement */

class db_statement {
public:
    const std::string sql;
    
    db_statement(const std::string sql);
    virtual ~db_statement();
    
    virtual void prepare() throw(db_exception) = 0;
    virtual db_result_set_ptr execute() throw(db_exception) = 0;
    
    virtual size_t getParamCount() = 0;
    virtual size_t getFieldCount() = 0;
    virtual long long getRowsChanged() = 0;
    virtual const db_field_metadata& getFieldMetaData(int field) = 0;

    virtual void setByte(int field, char value) = 0;
    virtual void setShort(int field, short value) = 0;
    virtual void setInt(int field, int value) = 0;
    virtual void setLongLong(int field, long long value) = 0;
    virtual void setFloat(int field, float value) = 0;
    virtual void setDouble(int field, double value) = 0;
    virtual void setString(int field, std::string value) = 0;
    virtual void setNull(int param) = 0;
};


/* db_result_set */

class db_result_set {
public:
    virtual ~db_result_set() {}
    
    virtual bool next() throw(db_exception) = 0;
    
    virtual bool isNull(int field) = 0;
    virtual char getByte(int field) = 0;
    virtual short getShort(int field) = 0;
    virtual int getInt(int field) = 0;
    virtual long long getLongLong(int field) = 0;
    virtual float getFloat(int field) = 0;
    virtual double getDouble(int field) = 0;
    virtual std::string getString(int field) = 0;
};


/* db_field_flag */

enum db_field_flag {
    db_field_flag_none = 0,
    db_field_flag_not_null = 1,        // NOT_NULL_FLAG            1       Field can't be NULL
    db_field_flag_primary_key = 2,     // PRI_KEY_FLAG             2       Field is part of a primary key
    db_field_flag_unique_key = 4,      // UNIQUE_KEY_FLAG          4       Field is part of a unique key
    db_field_flag_multiple_key = 8,    // MULTIPLE_KEY_FLAG        8       Field is part of a nonunique key
    db_field_flag_unsigned = 32,      // UNSIGNED_FLAG            32      Field has the unsigned attribute
    db_field_flag_zero_fill = 64,      // ZEROFILL_FLAG            64      Field has the zerofill attribute
    db_field_flag_binary = 128,       // BINARY_FLAG              128     Field has the binary attribute
    db_field_flag_enum = 256,         // ENUM_FLAG                256     Field is an enum
    db_field_flag_auto_increment = 512,// AUTO_INCREMENT_FLAG      512     Field is a autoincrement field
    db_field_flag_set = 2048,         // SET_FLAG                 2048    Field is a set
    db_field_flag_no_default = 4096,   // NO_DEFAULT_VALUE_FLAG    4096    Field doesn't have default value
    db_field_flag_numeric = 32768,    // NUM_FLAG                 32768   Field is numeric
};


/* db_field_type */

enum db_field_type {
    db_field_type_none,
    db_field_type_int8,               // MYSQL_TYPE_TINY          TINYINT field
    db_field_type_int16,              // MYSQL_TYPE_SHORT         SMALLINT field
    db_field_type_int24,              // MYSQL_TYPE_INT24         MEDIUMINT field
    db_field_type_int32,              // MYSQL_TYPE_LONG          INTEGER field
    db_field_type_int64,              // MYSQL_TYPE_LONGLONG      BIGINT field
    db_field_type_decimal,            // MYSQL_TYPE_NEWDECIMAL	Precision math DECIMAL or NUMERIC field (MySQL 5.0.3 and up)
    db_field_type_float,              // MYSQL_TYPE_FLOAT         FLOAT field
    db_field_type_double,             // MYSQL_TYPE_DOUBLE        DOUBLE or REAL field
    db_field_type_bit_field,           // MYSQL_TYPE_BIT           BIT field (MySQL 5.0.3 and up)
    db_field_type_time_stamp,          // MYSQL_TYPE_TIMESTAMP     TIMESTAMP field
    db_field_type_date,               // MYSQL_TYPE_DATE          DATE field
    db_field_type_time,               // MYSQL_TYPE_TIME          TIME field
    db_field_type_date_time,           // MYSQL_TYPE_DATETIME      DATETIME field
    db_field_type_year,               // MYSQL_TYPE_YEAR          YEAR field
    db_field_type_char,               // MYSQL_TYPE_STRING        CHAR or BINARY field
    db_field_type_var_char,            // MYSQL_TYPE_VAR_STRING	VARCHAR or VARBINARY field
    db_field_type_blob,               // MYSQL_TYPE_BLOB          BLOB or TEXT field (use max_length to determine the maximum length)
    db_field_type_set,                // MYSQL_TYPE_SET           SET field
    db_field_type_enum,               // MYSQL_TYPE_ENUM          ENUM field
    db_field_type_geometry,           // MYSQL_TYPE_GEOMETRY      Spatial field
    db_field_type_null,               // MYSQL_TYPE_NULL          NULL-type field
};


/* db_field_metadata */

struct db_field_type_name {
    const char* name;
    db_field_type type;
};

struct db_field_flag_name {
    const char* name;
    int flag;
};

class db_field_metadata {
public:
    static const char*      field_type_names[];
    static db_field_flag_name field_flag_names[];
    
    std::string         db_name;
    std::string         table_name;
    std::string         column_name;
    size_t              length;
    db_field_type        field_type;
    db_field_type        sql_type;
    unsigned int        flags;
    unsigned int        decimals;
    unsigned int        charset;
    
    virtual ~db_field_metadata() {}
    
    static std::string type_to_string(db_field_type type);
    static std::string flags_to_string(int flags);
};

#endif
