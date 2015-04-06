//
//  db.cc
//

#include "db.h"


/* db_exception */

std::string format_string(const char* fmt, ...)
{
    char msgbuf[128];
    va_list ap;
    
    va_start(ap, fmt);
    int len = vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
    va_end(ap);
    
    std::string str;
    if (len > 127) {
        char *bigbuf = new char[len + 1];
        va_start(ap, fmt);
        vsnprintf(bigbuf, len + 1, fmt, ap);
        va_end(ap);
        str = bigbuf;
        delete [] bigbuf;
    } else {
        str = msgbuf;
    }
    
    return str;
}

db_exception::db_exception(db_exception_code code, std::string message) : code(code), message(message) {}

db_exception_code db_exception::getCode() { return code; }
std::string db_exception::getMessage() { return message; }

const char* db_exception::what()
{
    if (_what.length() == 0) {
        std::stringstream ss;
        ss << "[db_exception code=" << code << " message=\"" << message << "\"]";
        _what = ss.str();
    }
    return _what.c_str();
}


/* db */

db_driver_map db::drivers;

void db::registerDriver(db_driver *driver)
{
    if (!driver) return;
    for (std::string driverName : driver->getDriverNames()) {
        if (drivers.find(driverName) != drivers.end()) return;
        drivers.insert(std::pair<std::string,db_driver*>(driverName, driver));
    }
}

db_connection_ptr db::openConnection(std::string db_uri, std::string username, std::string password) throw(db_exception)
{
    size_t colon_slash_slash = db_uri.find("://");
    if (colon_slash_slash == std::string::npos || colon_slash_slash <= 0) {
        throw db_exception(db_exception_code_invalid_uRI,
                           format_string("error parsing database driver uri: %s\n", db_uri.c_str()));
    }
    std::string driver = db_uri.substr(0, colon_slash_slash);
    db_driver_map::iterator di = drivers.find(driver);
    if (di != drivers.end()) {
        db_connection_ptr conn = (*di).second->createConnection(db_uri, username, password);
        conn->connect();
        return conn;
    }
    throw db_exception(db_exception_code_invalid_uRI,
                        format_string("error unknown database driver: %s\n", driver.c_str()));
}


/* db_driver */

db_driver::~db_driver() {}


/* db_connection_uri */

db_connection_uri::db_connection_uri(const std::string &db_uri, const std::string &username, const std::string &password)
: db_uri(db_uri), username(username), password(password) {}

db_connection_uri::~db_connection_uri() {}


/* db_metadata */

db_metadata::~db_metadata() {}


/* db_connection */

db_connection::db_connection(db_connection_uri_ptr conn_uri)
: conn_uri(conn_uri) {}

db_connection::~db_connection() {}


/* db_statement */

db_statement::db_statement(const std::string sql)
: sql(sql) {}

db_statement::~db_statement() {}


/* db_field_metadata */

const char* db_field_metadata::field_type_names[] = {
    "NONE",
    "TINYINT",                  // MYSQL_TYPE_TINY          TINYINT field
    "SMALLINT",                 // MYSQL_TYPE_SHORT         SMALLINT field
    "MEDIUMINT",                // MYSQL_TYPE_INT24         MEDIUMINT field
    "INTEGER",                  // MYSQL_TYPE_LONG          INTEGER field
    "BIGINT",                   // MYSQL_TYPE_LONGLONG      BIGINT field
    "DECIMAL",                  // MYSQL_TYPE_NEWDECIMAL	Precision math DECIMAL or NUMERIC field (MySQL 5.0.3 and up)
    "FLOAT",                    // MYSQL_TYPE_FLOAT         FLOAT field
    "DOUBLE",                   // MYSQL_TYPE_DOUBLE        DOUBLE or REAL field
    "BIT",                      // MYSQL_TYPE_BIT           BIT field (MySQL 5.0.3 and up)
    "TIMESTAMP",                // MYSQL_TYPE_TIMESTAMP     TIMESTAMP field
    "DATE",                     // MYSQL_TYPE_DATE          DATE field
    "TIME",                     // MYSQL_TYPE_TIME          TIME field
    "DATETIME",                 // MYSQL_TYPE_DATETIME      DATETIME field
    "YEAR",                     // MYSQL_TYPE_YEAR          YEAR field
    "CHAR",                     // MYSQL_TYPE_STRING        CHAR or BINARY field
    "VARCHAR",                  // MYSQL_TYPE_VAR_STRING	VARCHAR or VARBINARY field
    "BLOB",                     // MYSQL_TYPE_BLOB          BLOB or TEXT field (use max_length to determine the maximum length)
    "SET",                      // MYSQL_TYPE_SET           SET field
    "ENUM",                     // MYSQL_TYPE_ENUM          ENUM field
    "GEOMETRY",                 // MYSQL_TYPE_GEOMETRY      Spatial field
    "NULL",                     // MYSQL_TYPE_NULL          NULL-type field
    nullptr,
};

db_field_flag_name db_field_metadata::field_flag_names[] = {
    { "NotNull",        1},     // NOT_NULL_FLAG            1       Field can't be NULL
    { "PrimaryKey",     2},     // PRI_KEY_FLAG             2       Field is part of a primary key
    { "UniqueKey",      4},     // UNIQUE_KEY_FLAG          4       Field is part of a unique key
    { "MultipleKey",    8},     // MULTIPLE_KEY_FLAG        8       Field is part of a nonunique key
    { "Unsigned",       32},    // UNSIGNED_FLAG            32      Field has the unsigned attribute
    { "ZeroFill",       64},    // ZEROFILL_FLAG            64      Field has the zerofill attribute
    { "Binary",         128},   // BINARY_FLAG              128     Field has the binary attribute
    { "Enum",           256},   // ENUM_FLAG                256     Field is an enum
    { "AutoIncrement",  512},   // AUTO_INCREMENT_FLAG      512     Field is a autoincrement field
    { "Set",            2048},  // SET_FLAG                 2048    Field is a set
    { "NoDefault",      4096},  // NO_DEFAULT_VALUE_FLAG    4096    Field doesn't have default value
    { "Numeric",        32768}, // NUM_FLAG                 32768   Field is numeric
    { "None",           0 },
};

std::string db_field_metadata::type_to_string(db_field_type type)
{
    return field_type_names[type];
}

std::string db_field_metadata::flags_to_string(int flags)
{
    std::stringstream ss;
    db_field_flag_name *flagname_ent = field_flag_names;
    while (flagname_ent->flag) {
        if (flags & flagname_ent->flag) {
            if (ss.str().length() > 0) ss << ",";
            ss << flagname_ent->name;
        }
        flagname_ent++;
    }
    return ss.str();
}
