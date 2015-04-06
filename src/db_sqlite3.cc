//
//  db_sqlite3.cc
//

#include "sqlite3.h"

#include "db.h"
#include "db_sql_model.h"
#include "db_sql_parser.h"
#include "db_sql_parser_impl.h"

#include "db_sqlite3.h"


db_field_type_name sqltype_names[] = {
    { "TINYINT",    db_field_type_int8 },
    { "SMALLINT",   db_field_type_int16 },
    { "MEDIUMINT",  db_field_type_int24 },
    { "INT",        db_field_type_int32 },
    { "INTEGER",    db_field_type_int32 },
    { "BIGINT",     db_field_type_int64 },
    { "CHAR",       db_field_type_char },
    { "CHARACTER",  db_field_type_char },
    { "VARCHAR",    db_field_type_var_char },
    { "FLOAT",      db_field_type_float },
    { "DOUBLE",     db_field_type_double },
    { "REAL",       db_field_type_double },
    { "NUMERIC",    db_field_type_decimal },
    { "DECIMAL",    db_field_type_decimal },
    { "TEXT",       db_field_type_blob },
    { "BLOB",       db_field_type_blob },
    { "DATE",       db_field_type_date },
    { "TIME",       db_field_type_time },
    { "DATETIME",   db_field_type_date_time },
    { "TIMESTAMP",  db_field_type_time_stamp },
    { "YEAR",       db_field_type_year },
    { "NULL",       db_field_type_null },
    { "NONE",       db_field_type_none },
};

static db_field_type sqltype_to_type(const char* sqltype)
{
    db_field_type_name *typename_ent = sqltype_names;
    while (typename_ent->type) {
        if (strcasecmp(typename_ent->name, sqltype) == 0) {
            return typename_ent->type;
        }
        typename_ent++;
    }
    return typename_ent->type;
}

/* db_driver_sqlite3 */

db_driver_sqlite3 db_driver_sqlite3::driver;

db_driver_sqlite3::db_driver_sqlite3() {}

db_driver_sqlite3::~db_driver_sqlite3() {}

std::vector<std::string> db_driver_sqlite3::getDriverNames()
{
    std::vector<std::string> driverNames;
    driverNames.push_back("sqlite3");
    return driverNames;
}

db_connection_ptr db_driver_sqlite3::createConnection(const std::string &db_uri, const std::string &username, const std::string &password) throw(db_exception)
{
    db_connection_uri_ptr conn_uri(new db_connection_uri_sqlite3(db_uri, username, password));
    conn_uri->decode();
    return db_connection_ptr(new db_connection_sqlite3(conn_uri));
}


/* db_connection_uri_sqlite3 */

db_connection_uri_sqlite3::db_connection_uri_sqlite3(const std::string &db_uri, const std::string &username, const std::string &password)
: db_connection_uri(db_uri, username, password) {}

void db_connection_uri_sqlite3::decode() throw(db_exception)
{
    size_t colon_slash_slash = db_uri.find("://");
    if (colon_slash_slash == std::string::npos || colon_slash_slash <= 0) {
        throw db_exception(db_exception_code_invalid_uRI,
                           format_string("error parsing database driver uri: %s", db_uri.c_str()));
    }
    driver = db_uri.substr(0, colon_slash_slash);
    db_path = db_uri.substr(colon_slash_slash + 3);
}

std::string db_connection_uri_sqlite3::to_string() const
{
    std::stringstream ss;
    ss << driver << "://" << db_path;
    return ss.str();
}


/* db_metadata_sqlite3 */

db_metadata_sqlite3::db_metadata_sqlite3(db_connection_sqlite3 *conn) : conn(conn) {}
    
std::vector<std::string> db_metadata_sqlite3::getTableNames(std::string schema_name) throw(db_exception)
{
    std::vector<std::string> table_names;
    db_statement_ptr stmt = conn->prepareStatement("select name from sqlite_master where type = 'table';");
    db_result_set_ptr results = stmt->execute();
    while (results->next()) {
        table_names.push_back(results->getString(0));
    }
    return table_names;
}

db_table_definition_ptr db_metadata_sqlite3::getTableDefinition(std::string table_name, std::string schema_name) throw(db_exception)
{
    // fetch table create statement from the database
    db_statement_ptr stmt = conn->prepareStatement("select sql from sqlite_master where type = 'table' and name = ?;");
    stmt->setString(0, table_name);
    db_result_set_ptr results = stmt->execute();
    std::string table_sql;
    if (results->next()) {
        table_sql = results->getString(0);
    }
    
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


/* db_connection_sqlite3 */

db_connection_sqlite3::db_connection_sqlite3(db_connection_uri_ptr conn_uri)
: db_connection(conn_uri), db(nullptr) {}

db_connection_sqlite3::~db_connection_sqlite3()
{
    if (db && sqlite3_close(db) != SQLITE_OK) {
        db_connection_uri_sqlite3 *uri = static_cast<db_connection_uri_sqlite3*>(conn_uri.get());
        fprintf(stderr, "error closing database: %s: %s\n", sqlite3_errmsg(db), uri->db_uri.c_str());
    }
}

void db_connection_sqlite3::connect() throw(db_exception)
{
    db_connection_uri_sqlite3 *uri = static_cast<db_connection_uri_sqlite3*>(conn_uri.get());
    if (sqlite3_open(uri->db_path.c_str(), &db) != SQLITE_OK) {
        throw db_exception(db_exception_code_connect_failed,
                           format_string("error opening database: %s: %s", sqlite3_errmsg(db), uri->db_uri.c_str()));
    }
}

bool db_connection_sqlite3::getAutoCommit() throw(db_exception)
{
    return !!sqlite3_get_autocommit(db);
}

void db_connection_sqlite3::setAutoCommit(bool autocommit) throw(db_exception)
{
    char *errmsg = NULL;
    if (getAutoCommit() && !autocommit) {
        if (sqlite3_exec(db, "BEGIN;", NULL, NULL, &errmsg) != SQLITE_OK) {
            throw db_exception(db_exception_code_set_auto_commit_failed,
                               format_string("error set autocommit=%d: %s", autocommit, errmsg));
        }
    } else if (!getAutoCommit() && autocommit) {
        if (sqlite3_exec(db, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK) {
            throw db_exception(db_exception_code_set_auto_commit_failed,
                               format_string("error set autocommit=%d: %s", autocommit, errmsg));
        }
    }
}

void db_connection_sqlite3::commit() throw(db_exception)
{
    char *errmsg = NULL;
    if (getAutoCommit()) return;
    if (sqlite3_exec(db, "COMMIT;BEGIN;", NULL, NULL, &errmsg) != SQLITE_OK) {
        throw db_exception(db_exception_code_commit_failed,
                           format_string("commit failed: %s", errmsg));
    }
}

void db_connection_sqlite3::rollback() throw(db_exception)
{
    char *errmsg = NULL;
    if (getAutoCommit()) return;
    if (sqlite3_exec(db, "ROLLBACK;BEGIN;", NULL, NULL, &errmsg) != SQLITE_OK) {
        throw db_exception(db_exception_code_commit_failed,
                           format_string("rollback failed: %s", errmsg));
    }
}

db_metadata_ptr db_connection_sqlite3::getMetaData()
{
    return db_metadata_ptr(new db_metadata_sqlite3(this));
}

db_statement_ptr db_connection_sqlite3::prepareStatement(std::string sql) throw(db_exception)
{
    db_statement_ptr stmt(new db_statement_sqlite3(this, sql));
    stmt->prepare();
    return stmt;
}


/* db_statement_sqlite3 */

db_statement_sqlite3::db_statement_sqlite3(db_connection_sqlite3 *conn, const std::string sql)
: db_statement(sql), conn(conn), stmt(nullptr), prepare_rc(-1), param_count(0), field_count(0) {}

db_statement_sqlite3::~db_statement_sqlite3()
{
    if (stmt) {
        if (sqlite3_finalize(stmt) != SQLITE_OK) {
            fprintf(stderr, "error closing statement: %s: %s\n", sqlite3_errmsg(conn->db), sql.c_str());
        }
    }
}

size_t db_statement_sqlite3::getParamCount()
{
    return param_count;
}

size_t db_statement_sqlite3::getFieldCount()
{
    return field_count;
}

long long db_statement_sqlite3::getRowsChanged()
{
    return rows_changed;
}

const db_field_metadata& db_statement_sqlite3::getFieldMetaData(int field)
{
    return field_metadata[field];
}

void db_statement_sqlite3::prepare() throw(db_exception)
{
    if ((prepare_rc = sqlite3_prepare_v2(conn->db, sql.c_str(), -1, &stmt, NULL)) != SQLITE_OK) {
        throw db_exception(db_exception_code_prepare_failed,
                           format_string("error preparing statement: %s: %s", sqlite3_errmsg(conn->db), sql.c_str()));
    }
    
    param_count = sqlite3_bind_parameter_count(stmt);
    field_count = sqlite3_column_count(stmt);
}

db_result_set_ptr db_statement_sqlite3::execute() throw(db_exception)
{
    if (sqlite3_reset(stmt) != SQLITE_OK) {
        throw db_exception(db_exception_code_execute_failed,
                           format_string("error resetting statement: %s: %s", sqlite3_errmsg(conn->db), sql.c_str()));
    }
    
    step_rc = sqlite3_step(stmt);
    if (step_rc != SQLITE_ROW && step_rc != SQLITE_DONE) {
        throw db_exception(db_exception_code_execute_failed,
                           format_string("error executing statement: %s: %s", sqlite3_errmsg(conn->db), sql.c_str()));
    }
    
    rows_changed = sqlite3_total_changes(conn->db);

    field_metadata.resize(field_count);
    for (int i = 0; i < field_count; i++) {
        db_field_metadata *meta = &field_metadata[i];
        const char* column_name = sqlite3_column_name(stmt, i);
        const char* table_name = sqlite3_column_table_name(stmt, i);
        const char* db_name = sqlite3_column_database_name(stmt, i);
        meta->column_name = column_name ? column_name : "";
        meta->table_name = table_name ? table_name : "";
        meta->db_name = db_name ? db_name : "";
        int sq_type = sqlite3_column_type(stmt, i);
        db_field_type type;
        switch (sq_type) {
            case SQLITE_INTEGER:    type = db_field_type_int64;       break;
            case SQLITE_FLOAT:      type = db_field_type_double;      break;
            case SQLITE_BLOB:       type = db_field_type_blob;        break;
            case SQLITE_TEXT:       type = db_field_type_char;        break;
            case SQLITE_NULL:       type = db_field_type_null;        break;
            default:                type = db_field_type_none;        break;
        }
        meta->field_type = type;
        meta->charset = 0;
        meta->length = meta->decimals = 0;
        const char* declstr = sqlite3_column_decltype(stmt, i);
        std::string decl = declstr ? declstr : "";
        size_t decl_open_paren = decl.find("(");
        if (decl_open_paren != std::string::npos) {
            size_t decl_close_paren = decl.find(")");
            if (decl_close_paren != std::string::npos && decl_open_paren < decl_close_paren) {
                std::string size_spec = decl.substr(decl_open_paren + 1, decl_close_paren - decl_open_paren - 1);
                size_t decl_comma = size_spec.find(",");
                if (decl_comma != std::string::npos) {
                    meta->length = atoi(size_spec.substr(0, decl_comma).c_str());
                    meta->decimals = atoi(size_spec.substr(decl_comma + 1).c_str());
                } else {
                    meta->length = atoi(size_spec.c_str());
                }
                if (sq_type == SQLITE_INTEGER || sq_type == SQLITE_FLOAT) {
                    meta->length += 2;
                }
            }
            meta->sql_type = sqltype_to_type(decl.substr(0, decl_open_paren).c_str());
        } else {
            meta->sql_type = sqltype_to_type(decl.c_str());
            switch (meta->sql_type) {
                case db_field_type_int8: meta->length = 4; break;
                case db_field_type_int16: meta->length = 6; break;
                case db_field_type_int32: meta->length = 11; break;
                case db_field_type_int64: meta->length = 20; break;
                case db_field_type_float: meta->length = 12; break;
                case db_field_type_double: meta->length = 22; break;
                default: meta->length = 20; break; // no idea
            }
        }
#if DEBUG
        printf("Field %u name=%-16s table=%-16s db=%-10s field_type=%-10s sql_type=%-10s length=%-5lu decimals=%-3d flags=%s\n",
               (unsigned int)i, meta->column_name.c_str(), meta->table_name.c_str(), meta->db_name.c_str(),
               db_field_metadata::type_to_string(meta->field_type).c_str(), db_field_metadata::type_to_string(meta->sql_type).c_str(),
               meta->length, meta->decimals, db_field_metadata::flags_to_string(meta->flags).c_str());
#endif
    }
    
    return db_result_set_ptr(new db_result_set_sqlite3(this));
}

void db_statement_sqlite3::setByte(int param, char value)
{
    sqlite3_bind_int(stmt, param + 1, (int)value);
}

void db_statement_sqlite3::setShort(int param, short value)
{
    sqlite3_bind_int(stmt, param + 1, (int)value);
}

void db_statement_sqlite3::setInt(int param, int value)
{
    sqlite3_bind_int(stmt, param + 1, value);
}

void db_statement_sqlite3::setLongLong(int param, long long value)
{
    sqlite3_bind_int64(stmt, param + 1, value);
}

void db_statement_sqlite3::setFloat(int param, float value)
{
    sqlite3_bind_double(stmt, param + 1, (double)value);
}

void db_statement_sqlite3::setDouble(int param, double value)
{
    sqlite3_bind_double(stmt, param + 1, value);
}

void db_statement_sqlite3::setString(int param, std::string value)
{
    sqlite3_bind_text(stmt, param + 1, value.c_str(), (int)value.length(), SQLITE_TRANSIENT);
}

void db_statement_sqlite3::setNull(int param)
{
    sqlite3_bind_null(stmt, param + 1);
}


/* db_result_set_sqlite3 */

db_result_set_sqlite3::db_result_set_sqlite3(db_statement_sqlite3 *stmt) : stmt(stmt), step_rc(SQLITE_OK) {}

db_result_set_sqlite3::~db_result_set_sqlite3() {}

bool db_result_set_sqlite3::next() throw(db_exception)
{
    if (stmt->step_rc == SQLITE_DONE) {
        stmt->step_rc = SQLITE_OK;
        return false;
    }
    if (stmt->step_rc == SQLITE_ROW) {
        stmt->step_rc = SQLITE_OK;
        return true;
    }
    if (step_rc == SQLITE_DONE) {
        return false;
    }
    step_rc = sqlite3_step(stmt->stmt);
    if (step_rc == SQLITE_ROW) {
        return true;
    } else if (step_rc == SQLITE_DONE) {
        return false;
    } else {
        throw db_exception(db_exception_code_cursor_error,
                           format_string("error fetching next row: %s: %s", sqlite3_errmsg(stmt->conn->db), stmt->sql.c_str()));
        return false;
    }
}

bool db_result_set_sqlite3::isNull(int field)
{
    return sqlite3_column_type(stmt->stmt, field) == SQLITE_NULL;
}

char db_result_set_sqlite3::getByte(int field)
{
    return (char)sqlite3_column_int(stmt->stmt, field);
}

short db_result_set_sqlite3::getShort(int field)
{
    return (short)sqlite3_column_int(stmt->stmt, field);
}

int db_result_set_sqlite3::getInt(int field)
{
    return sqlite3_column_int(stmt->stmt, field);
}

long long db_result_set_sqlite3::getLongLong(int field)
{
    return sqlite3_column_int64(stmt->stmt, field);
}

float db_result_set_sqlite3::getFloat(int field)
{
    return (float)sqlite3_column_double(stmt->stmt, field);
}

double db_result_set_sqlite3::getDouble(int field)
{
    return sqlite3_column_double(stmt->stmt, field);
}

std::string db_result_set_sqlite3::getString(int field)
{
    const char* str = (const char*)sqlite3_column_text(stmt->stmt, field);
    return str ? str : "";
}
