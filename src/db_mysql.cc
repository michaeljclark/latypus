//
//  db_mysql.cc
//

#include <stdio.h>
#include <mysql.h>

#include "db.h"
#include "db_sql_model.h"
#include "db_sql_parser.h"
#include "db_sql_parser_impl.h"

#include "db_mysql.h"


/* db_field_flag to MySQL flag mapping */

struct db_field_flag_mysql {
    db_field_flag edb_flag;
    int mysql_flag;
};

static const db_field_flag_mysql mysql_flags[] = {
    { db_field_flag_not_null,          NOT_NULL_FLAG           }, // 1     Field can't be NULL
    { db_field_flag_primary_key,       PRI_KEY_FLAG            }, // 2     Field is part of a primary key
    { db_field_flag_unique_key,        UNIQUE_KEY_FLAG         }, // 4     Field is part of a unique key
    { db_field_flag_multiple_key,      MULTIPLE_KEY_FLAG       }, // 8     Field is part of a nonunique key
    { db_field_flag_unsigned,          UNSIGNED_FLAG           }, // 32    Field has the unsigned attribute
    { db_field_flag_zero_fill,         ZEROFILL_FLAG           }, // 64    Field has the zerofill attribute
    { db_field_flag_binary,            BINARY_FLAG             }, // 128   Field has the binary attribute
    { db_field_flag_enum,              ENUM_FLAG               }, // 256   Field is an enum
    { db_field_flag_auto_increment,    AUTO_INCREMENT_FLAG     }, // 512   Field is a autoincrement field
    { db_field_flag_set,               SET_FLAG                }, // 2048  Field is a set
    { db_field_flag_no_default,        NO_DEFAULT_VALUE_FLAG   }, // 4096  Field doesn't have default value
    { db_field_flag_numeric,           NUM_FLAG                }, // 32768 Field is numeric
    { db_field_flag_none,              0                       }  // end of array marker
};


/* db_driver_mysql */

db_driver_mysql db_driver_mysql::driver;

db_driver_mysql::db_driver_mysql() {}

db_driver_mysql::~db_driver_mysql() {}

std::vector<std::string> db_driver_mysql::getDriverNames()
{
    std::vector<std::string> driverNames;
    driverNames.push_back("mysql");
    return driverNames;
}

db_connection_ptr db_driver_mysql::createConnection(const std::string &db_uri, const std::string &username, const std::string &password) throw(db_exception)
{
    db_connection_uri_ptr conn_uri(new db_connection_uri_mysql(db_uri, username, password));
    conn_uri->decode();
    return db_connection_ptr(new db_connection_mysql(conn_uri));
}


/* db_connection_uri_mysql */

db_connection_uri_mysql::db_connection_uri_mysql(const std::string &db_uri, const std::string &username, const std::string &password)
: db_connection_uri(db_uri, username, password) {}

void db_connection_uri_mysql::decode() throw(db_exception)
{
    size_t colon_slash_slash = db_uri.find("://");
    if (colon_slash_slash == std::string::npos || colon_slash_slash <= 0) {
        throw db_exception(db_exception_code_invalid_uRI,
                           format_string("error parsing database driver uri: %s", db_uri.c_str()));
    }
    driver = db_uri.substr(0, colon_slash_slash);
    std::string host_database = db_uri.substr(colon_slash_slash + 3);
    
    size_t slash = host_database.find("/");
    if (slash == std::string::npos) {
        throw db_exception(db_exception_code_invalid_uRI,
                           format_string("error parsing database driver uri: %s", db_uri.c_str()));
    }
    std::string host_port = host_database.substr(0, slash);
    std::string db_options = host_database.substr(slash + 1);
    
    size_t host_port_colon = host_port.find(":");
    int port = 0;
    if (host_port_colon != std::string::npos) {
        host = host_port.substr(host_port_colon + 1);
        port = atoi(host_port.substr(0, host_port_colon).c_str());
    } else {
        host = host_port;
    }
    if (host == "") {
        host = "localhost";
    }
    
    size_t db_options_question_mark = db_options.find("?");
    if (db_options_question_mark != std::string::npos) {
        options = db_options.substr(db_options_question_mark + 1);
        db_name = db_options.substr(0, db_options_question_mark);
    } else {
        db_name = db_options;
        options = "";
    }
}

std::string db_connection_uri_mysql::to_string() const
{
    std::stringstream ss;
    ss << driver << "://" << username << "@" << host;
    if (port > 0) ss << ":" << port;
    ss << "/" << db_name;
    if (options.length() > 0) ss << "?" << options;
    return ss.str();
}


/* db_metadata_mysql */

db_metadata_mysql::db_metadata_mysql(db_connection_mysql *conn) : conn(conn) {}

std::vector<std::string> db_metadata_mysql::getTableNames(std::string schema_name) throw(db_exception)
{
    std::vector<std::string> table_names;
    if (schema_name.length() == 0) {
        db_connection_uri_mysql *uri = static_cast<db_connection_uri_mysql*>(conn->conn_uri.get());
        schema_name = uri->db_name;
    }
    db_statement_ptr stmt = conn->prepareStatement("select table_name from INFORMATION_SCHEMA.TABLES where schema_name = ?;");
    stmt->setString(0, schema_name);
    db_result_set_ptr results = stmt->execute();
    while (results->next()) {
        table_names.push_back(results->getString(0));
    }
    return table_names;
}


db_table_definition_ptr db_metadata_mysql::getTableDefinition(std::string table_name, std::string schema_name) throw(db_exception)
{
    if (schema_name.length() == 0) {
        db_connection_uri_mysql *uri = static_cast<db_connection_uri_mysql*>(conn->conn_uri.get());
        schema_name = uri->db_name;
    }
    
    // fetch table create statement from the database
    std::string query = "show create table " + schema_name + "." + table_name;
    
    MYSQL_RES *result = NULL;
    if (mysql_query(conn->mysql, query.c_str()))
    {
        fprintf(stderr, "Couldn't execute '%s': %s (%d)\n",
                query.c_str(), mysql_error(conn->mysql), mysql_errno(conn->mysql));
        return db_table_definition_ptr();
    }
    if (!(result = mysql_store_result(conn->mysql))) {
        fprintf(stderr, "Couldn't store result '%s': %s (%d)\n",
                query.c_str(), mysql_error(conn->mysql), mysql_errno(conn->mysql));
        return db_table_definition_ptr();
    }
    
    std::string table_sql;
    if (mysql_num_rows(result) == 1 && mysql_num_fields(result) == 2) {
        MYSQL_ROW row = mysql_fetch_row(result);
        table_sql = row[1];
    }
    mysql_free_result(result);
    
    // parse the create statement and build abstract syntax tree
    db_sql_parser_impl sqlparser;
    sqlparser.execute(table_sql.c_str(), table_sql.size(), true);
    if (sqlparser.statements.size() == 0) {
        throw db_exception(db_exception_code_metadata_error, "failed to parse create table statement");
    }
    db_sql_statement_ptr table_statement = sqlparser.statements[0];
    db_table_definition_ptr table_def = std::dynamic_pointer_cast<db_table_definition>(table_statement);
    
    return table_def;
}


/* db_connection_mysql */

db_connection_mysql::db_connection_mysql(db_connection_uri_ptr conn_uri)
: db_connection(conn_uri), mysql(nullptr), autocommit(0) {}

db_connection_mysql::~db_connection_mysql()
{
    if (mysql) {
        mysql_close(mysql);
    }
}

void db_connection_mysql::connect() throw(db_exception)
{
    if ((mysql = mysql_init(nullptr)) == nullptr) {
        throw db_exception(db_exception_code_connect_failed,
                           "insufficient memory");
    };
    
    db_connection_uri_mysql *uri = static_cast<db_connection_uri_mysql*>(conn_uri.get());
    
    if (mysql_real_connect(mysql, uri->host.c_str(), uri->username.c_str(), uri->password.c_str(),
                           uri->db_name.c_str(), uri->port ? uri->port : MYSQL_PORT, nullptr, 0) == nullptr) {
        throw db_exception(db_exception_code_connect_failed,
                           format_string("error opening database: %s: %s", mysql_error(mysql), uri->db_uri.c_str()));
    }
    
    setAutoCommit(1);
}

bool db_connection_mysql::getAutoCommit() throw(db_exception)
{
    return autocommit;
}

void db_connection_mysql::setAutoCommit(bool autocommit) throw(db_exception)
{
    autocommit = !!autocommit;
    if (autocommit != this->autocommit) {
        this->autocommit = autocommit;
        if (mysql_query(mysql, format_string("SET autocommit=%d", autocommit).c_str()) != 0) {
            throw db_exception(db_exception_code_set_auto_commit_failed,
                               format_string("error set autocommit=%d: %s", autocommit, mysql_error(mysql)));
        }
    }
}

void db_connection_mysql::commit() throw(db_exception)
{
    if (mysql_query(mysql, "commit") != 0) {
        throw db_exception(db_exception_code_commit_failed,
                           format_string("commit failed: %s", mysql_error(mysql)));
    }
}

void db_connection_mysql::rollback() throw(db_exception)
{
    if (mysql_query(mysql, "rollback") != 0) {
        throw db_exception(db_exception_code_rollback_failed,
                           format_string("rollback failed: %s", autocommit, mysql_error(mysql)));
    }
}

db_metadata_ptr db_connection_mysql::getMetaData()
{
    return db_metadata_ptr(new db_metadata_mysql(this));
}

db_statement_ptr db_connection_mysql::prepareStatement(std::string sql) throw(db_exception)
{
    db_statement_ptr stmt(new db_statement_mysql(this, sql));
    stmt->prepare();
    return stmt;
}


/* db_statement_mysql */

db_statement_mysql::db_statement_mysql(db_connection_mysql *conn, const std::string sql)
: db_statement(sql), conn(conn), rowdata(nullptr), rowdata_size(0) {}

db_statement_mysql::~db_statement_mysql()
{
    if (stmt) {
        mysql_stmt_free_result(stmt);
        if (mysql_stmt_close(stmt) != 0) {
            fprintf(stderr, "error closing statement: %s: %s\n", mysql_error(conn->mysql), sql.c_str());
        }
    }
}

size_t db_statement_mysql::getParamCount()
{
    return params.size();
}

size_t db_statement_mysql::getFieldCount()
{
    return fields.size();
}

long long db_statement_mysql::getRowsChanged()
{
    return rows_changed;
}

const db_field_metadata& db_statement_mysql::getFieldMetaData(int field)
{
    return field_metadata[field];
}

static int decode_mysql_flags(int flags)
{
    int edb_flags = 0;
    const db_field_flag_mysql *flag_ent = mysql_flags;
    while (flag_ent->edb_flag) {
        if (flags & flag_ent->mysql_flag) edb_flags |= flag_ent->edb_flag;
        flag_ent++;
    }
    return edb_flags;
}

inline size_t align_size(size_t size, size_t alignment) { return (size + alignment-1) & -alignment; }

void db_statement_mysql::prepare() throw(db_exception)
{
    if ((stmt = mysql_stmt_init(conn->mysql)) == nullptr) {
        throw db_exception(db_exception_code_prepare_failed,
                           format_string("error initializing statement: %s: %s", mysql_error(conn->mysql), sql.c_str()));
    }
    
    if (mysql_stmt_prepare(stmt, sql.c_str(), sql.size()) != 0) {
        throw db_exception(db_exception_code_prepare_failed,
                           format_string("error preparing statement: %s: %s", mysql_error(conn->mysql), sql.c_str()));
    }
    
    size_t param_count = mysql_stmt_param_count(stmt);
    params.resize(param_count);
    paramdata.resize(param_count);
    
    size_t field_count = mysql_stmt_field_count(stmt);
    fields.resize(field_count);
    field_metadata.resize(field_count);
    field_size_offset.resize(field_count);
    
    MYSQL_RES *result = mysql_stmt_result_metadata(stmt);
    if (!result) return; // empty for statements that don't return results
    
    rowdata_size = 0;
    for(size_t i = 0; i < field_count; i++)
    {
        MYSQL_FIELD *field = mysql_fetch_field_direct(result, (unsigned int)i);
        
        size_t size;
        db_field_type type;
        switch (field->type) {
            case MYSQL_TYPE_TINY:       type = db_field_type_int8;        size = 1;                   break;
            case MYSQL_TYPE_SHORT:      type = db_field_type_int16;       size = 2;                   break;
            case MYSQL_TYPE_INT24:      type = db_field_type_int24;       size = 3;                   break;
            case MYSQL_TYPE_LONG:       type = db_field_type_int32;       size = 4;                   break;
            case MYSQL_TYPE_LONGLONG:   type = db_field_type_int64;       size = 8;                   break;
            case MYSQL_TYPE_NEWDECIMAL: type = db_field_type_decimal;     size = field->length;       break;
            case MYSQL_TYPE_FLOAT:      type = db_field_type_float;       size = 4;                   break;
            case MYSQL_TYPE_DOUBLE:     type = db_field_type_double;      size = 8;                   break;
            case MYSQL_TYPE_BIT:        type = db_field_type_bit_field;    size = field->length;       break; // correct size?
            case MYSQL_TYPE_TIMESTAMP:  type = db_field_type_time_stamp;   size = sizeof(MYSQL_TIME);  break;
            case MYSQL_TYPE_DATE:       type = db_field_type_date;        size = sizeof(MYSQL_TIME);  break;
            case MYSQL_TYPE_TIME:       type = db_field_type_time;        size = sizeof(MYSQL_TIME);  break;
            case MYSQL_TYPE_DATETIME:   type = db_field_type_date_time;    size = sizeof(MYSQL_TIME);  break;
            case MYSQL_TYPE_YEAR:       type = db_field_type_year;        size = 4;                   break;
            case MYSQL_TYPE_STRING:     type = db_field_type_char;        size = field->length + 1;   break;
            case MYSQL_TYPE_VAR_STRING: type = db_field_type_var_char;     size = field->length + 1;   break;
            case MYSQL_TYPE_BLOB:       type = db_field_type_blob;        size = 0;                   break; // handle truncation
            case MYSQL_TYPE_SET:        type = db_field_type_set;         size = field->length;       break; // correct size?
            case MYSQL_TYPE_ENUM:       type = db_field_type_enum;        size = field->length;       break; // correct size?
            case MYSQL_TYPE_GEOMETRY:   type = db_field_type_geometry;    size = field->length;       break; // correct size?
            default:                    type = db_field_type_none;        size = 0; break;
        }

        db_field_metadata *meta = &field_metadata[i];
        meta->field_type = type;
        meta->sql_type = type;
        meta->db_name = field->db;
        meta->table_name = field->table;
        meta->column_name = field->name;
        meta->length = field->length;
        meta->flags = decode_mysql_flags(field->flags);
        meta->decimals = field->decimals;
        meta->charset = field->charsetnr; // use our own charset codes?
        
        MYSQL_BIND *f = &fields[i];
        f->buffer_type = field->type;
        f->buffer_length = size;

        size += sizeof(unsigned long) + sizeof(my_bool) + sizeof(my_bool);  /* room for length, is_null, error */
        size = align_size(size, 8); /* wastage, todo: align to 4 bytes and special case int64 */
        field_size_offset[i] = std::pair<size_t,size_t>(size, rowdata_size);
        rowdata_size += size;
        
#if DEBUG
        printf("Field %u name=%-16s table=%-16s db=%-10s field_type=%-10s sql_type=%-10s length=%-5lu decimals=%-3d flags=%s\n",
               (unsigned int)i, meta->column_name.c_str(), meta->table_name.c_str(), meta->db_name.c_str(),
               db_field_metadata::type_to_string(meta->field_type).c_str(), db_field_metadata::type_to_string(meta->sql_type).c_str(),
               meta->length, meta->decimals, db_field_metadata::flags_to_string(meta->flags).c_str());
#endif
    }
    mysql_free_result(result);
    
    // allocate row data and set result pointers
    rowdata = std::unique_ptr<unsigned char>(new unsigned char[rowdata_size]);
    for(size_t i = 0; i < field_count; i++)
    {
        size_t size = field_size_offset[i].first;
        size_t offset = field_size_offset[i].second;
        unsigned char *data_start = rowdata.get() + offset;
        unsigned char *data_end = data_start + size;
        MYSQL_BIND *f = &fields[i];
        f->buffer = data_start;
        f->is_null = (my_bool*)(data_end - sizeof(unsigned long) - sizeof(my_bool) - sizeof(my_bool));
        f->error = (my_bool*)(data_end - sizeof(unsigned long) - sizeof(my_bool));
        f->length = (unsigned long*)(data_end - sizeof(unsigned long));
    }
    
    // Bind result
    if (mysql_stmt_bind_result(stmt, &fields[0]) != 0) {
        throw db_exception(db_exception_code_prepare_failed,
                           format_string("error binding fields: %s: %s", mysql_error(conn->mysql), sql.c_str()));
    }
}

db_result_set_ptr db_statement_mysql::execute() throw(db_exception)
{
    if (params.size() > 0) {
        if (mysql_stmt_bind_param(stmt, &params[0]) != 0) {
            throw db_exception(db_exception_code_execute_failed,
                               format_string("error binding parameters: %s: %s", mysql_error(conn->mysql), sql.c_str()));
        }
    }
    
    if (mysql_stmt_reset(stmt) != 0) {
        throw db_exception(db_exception_code_execute_failed,
                           format_string("error resetting statement: %s: %s", mysql_error(conn->mysql), sql.c_str()));
    }
    
    if (mysql_stmt_execute(stmt) != 0) {
        throw db_exception(db_exception_code_execute_failed,
                           format_string("error executing statement: %s: %s", mysql_error(conn->mysql), sql.c_str()));
    }

    rows_changed = mysql_stmt_affected_rows(stmt);
    
    return db_result_set_ptr(new db_result_set_mysql(this));
}

void db_statement_mysql::setByte(int param, char value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = sizeof(char);
    p->buffer_type = MYSQL_TYPE_TINY;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    *(char*)p->buffer = value;
}

void db_statement_mysql::setShort(int param, short value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = sizeof(short);
    p->buffer_type = MYSQL_TYPE_SHORT;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    *(short*)p->buffer = value;
}

void db_statement_mysql::setInt(int param, int value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = sizeof(int);
    p->buffer_type = MYSQL_TYPE_LONG;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    *(int*)p->buffer = value;
}

void db_statement_mysql::setLongLong(int param, long long value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = sizeof(long long);
    p->buffer_type = MYSQL_TYPE_LONGLONG;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    *(long long*)p->buffer = value;
}

void db_statement_mysql::setFloat(int param, float value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = sizeof(float);
    p->buffer_type = MYSQL_TYPE_FLOAT;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    *(float*)p->buffer = value;
}

void db_statement_mysql::setDouble(int param, double value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = sizeof(double);
    p->buffer_type = MYSQL_TYPE_DOUBLE;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    *(double*)p->buffer = value;
}

void db_statement_mysql::setString(int param, std::string value)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    const size_t len = value.size();
    p->buffer_type = MYSQL_TYPE_STRING;
    p->buffer_length = len;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(new unsigned char[len]);
    p->buffer = paramdata[param].get();
    memcpy(p->buffer, value.c_str(), len);
}

void db_statement_mysql::setNull(int param)
{
    if (param >= params.size()) return;
    MYSQL_BIND *p = &params[param];
    p->buffer_type = MYSQL_TYPE_NULL;
    p->buffer_length = 0;
    p->is_unsigned = false;
    p->is_null = nullptr;
    paramdata[param] = std::unique_ptr<unsigned char>(nullptr);
    p->buffer = paramdata[param].get();
}


/* db_result_set_mysql */

db_result_set_mysql::db_result_set_mysql(db_statement_mysql *stmt) : stmt(stmt) {}

db_result_set_mysql::~db_result_set_mysql() {}

bool db_result_set_mysql::next() throw(db_exception)
{
    memset(stmt->rowdata.get(), 0, stmt->rowdata_size);
    int result = mysql_stmt_fetch(stmt->stmt);
    if (result == 0) return true;
    if (result == MYSQL_NO_DATA) return false;
    throw db_exception(db_exception_code_cursor_error,
                       format_string("error fetching next row: %s: %s", mysql_error(stmt->conn->mysql), stmt->sql.c_str()));
}

bool db_result_set_mysql::isNull(int field)
{
    if (field < stmt->fields.size()) {
        return getRowData(field).is_null;
    }
    return false;
}

char db_result_set_mysql::getByte(int field)
{
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            return (char)*getRowPtr<char>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            return (char)*getRowPtr<short>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            return (char)*getRowPtr<int>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            return (char)*getRowPtr<long long>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            return (char)*getRowPtr<float>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            return (char)*getRowPtr<double>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal) {
            return (char)strtoll(getRowPtr<char>(field), (char **)NULL, 10);
        }
    }
    return 0;
}

short db_result_set_mysql::getShort(int field)
{
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            return (short)*getRowPtr<char>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            return (short)*getRowPtr<short>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            return (short)*getRowPtr<int>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            return (short)*getRowPtr<long long>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            return (short)*getRowPtr<float>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            return (short)*getRowPtr<double>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal) {
            return (short)strtoll(getRowPtr<char>(field), (char **)NULL, 10);
        }
    }
    return 0;
}

int db_result_set_mysql::getInt(int field)
{
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            return (int)*getRowPtr<char>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            return (int)*getRowPtr<short>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            return (int)*getRowPtr<int>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            return (int)*getRowPtr<long long>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            return (int)*getRowPtr<float>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            return (int)*getRowPtr<double>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal) {
            return (int)strtoll(getRowPtr<char>(field), (char **)NULL, 10);
        }
    }
    return 0;
}

long long db_result_set_mysql::getLongLong(int field)
{
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            return (long long)*getRowPtr<char>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            return (long long)*getRowPtr<short>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            return (long long)*getRowPtr<int>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            return (long long)*getRowPtr<long long>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            return (long long)*getRowPtr<float>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            return (long long)*getRowPtr<double>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal) {
            return (long long)strtoll(getRowPtr<char>(field), (char **)NULL, 10);
        }
    }
    return 0;
}

float db_result_set_mysql::getFloat(int field)
{
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            return (float)*getRowPtr<char>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            return (float)*getRowPtr<short>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            return (float)*getRowPtr<int>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            return (float)*getRowPtr<long long>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            return (float)*getRowPtr<float>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            return (float)*getRowPtr<double>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal) {
            return (float)atof(getRowPtr<char>(field));
        }
    }
    return 0;
}

double db_result_set_mysql::getDouble(int field)
{
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            return (double)*getRowPtr<char>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            return (double)*getRowPtr<short>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            return (double)*getRowPtr<int>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            return (double)*getRowPtr<long long>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            return (double)*getRowPtr<float>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            return (double)*getRowPtr<double>(field);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal) {
            return (double)atof(getRowPtr<char>(field));
        }
    }
    return 0;
}

std::string db_result_set_mysql::getString(int field)
{
    char buf[32];
    if (field < stmt->fields.size()) {
        if (stmt->field_metadata[field].field_type == db_field_type_int8) {
            sprintf(buf, "%hhd", *getRowPtr<char>(field));
            return std::string(buf);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int16) {
            sprintf(buf, "%hd", *getRowPtr<short>(field));
            return std::string(buf);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int32) {
            sprintf(buf, "%d", *getRowPtr<int>(field));
            return std::string(buf);
        } else if (stmt->field_metadata[field].field_type == db_field_type_int64) {
            sprintf(buf, "%lld", *getRowPtr<long long>(field));
            return std::string(buf);
        } else if (stmt->field_metadata[field].field_type == db_field_type_float) {
            sprintf(buf, "%f", *getRowPtr<float>(field));
            return std::string(buf);
        } else if (stmt->field_metadata[field].field_type == db_field_type_double) {
            sprintf(buf, "%lf", *getRowPtr<double>(field));
            return std::string(buf);
        } else if (stmt->field_metadata[field].field_type == db_field_type_char ||
                   stmt->field_metadata[field].field_type == db_field_type_var_char ||
                   stmt->field_metadata[field].field_type == db_field_type_decimal ||
                   stmt->field_metadata[field].field_type == db_field_type_blob) {
            return getRowPtr<char>(field);
        }
    }
    return "";
}
