//
//  db_sqlite3.h
//

#ifndef db_sqlite3_h
#define db_sqlite3_h

struct sqlite3;
struct sqlite3_stmt;

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

class db_driver_sqlite3;
class db_connection_sqlite3;
class db_statement_sqlite3;


/* db_driver_sqlite3 */

class db_driver_sqlite3 : public db_driver
{
public:
    static db_driver_sqlite3 driver;
    
    db_driver_sqlite3();
    ~db_driver_sqlite3();
    
    std::vector<std::string> getDriverNames();
    db_connection_ptr createConnection(const std::string &db_uri, const std::string &username, const std::string &password) throw(db_exception);
};


/* db_connection_uri_sqlite3 */

class db_connection_uri_sqlite3 : public db_connection_uri
{
public:
    std::string driver;
    std::string db_path;
    
    db_connection_uri_sqlite3(const std::string &db_uri, const std::string &username, const std::string &password);

    void decode() throw(db_exception);
    std::string to_string() const;
};


/* db_metadata_sqlite3 */

class db_metadata_sqlite3 : public db_metadata
{
private:
    db_connection_sqlite3 *conn;
    
public:
    db_metadata_sqlite3(db_connection_sqlite3 *conn);
    
    std::vector<std::string> getTableNames(std::string schema_name) throw(db_exception);
    db_table_definition_ptr getTableDefinition(std::string table_name, std::string schema_name) throw(db_exception);
};


/* db_connection_sqlite3 */

class db_connection_sqlite3 : public db_connection
{
private:
    friend class db_statement_sqlite3;
    friend class db_result_set_sqlite3;
    
    sqlite3 *db;
    
public:
    db_connection_sqlite3(db_connection_uri_ptr conn_info);
    ~db_connection_sqlite3();
    
    void connect() throw(db_exception);
    bool getAutoCommit() throw(db_exception);
    void setAutoCommit(bool autocommit) throw(db_exception);
    void commit() throw(db_exception);
    void rollback() throw(db_exception);
    db_metadata_ptr getMetaData();
    db_statement_ptr prepareStatement(std::string sql) throw(db_exception);
};


/* db_statement_sqlite3 */

class db_statement_sqlite3 : public db_statement
{
private:
    friend class db_result_set_sqlite3;
    
    db_connection_sqlite3 *conn;
    sqlite3_stmt *stmt;
    int prepare_rc;
    int step_rc;
    int param_count;
    int field_count;
    long long rows_changed;
    db_field_metadata_list field_metadata;
    
public:
    db_statement_sqlite3(db_connection_sqlite3 *conn, const std::string sql);
    ~db_statement_sqlite3();
    
    size_t getParamCount();
    size_t getFieldCount();
    long long getRowsChanged();
    const db_field_metadata& getFieldMetaData(int field);
    
    void prepare() throw(db_exception);
    db_result_set_ptr execute() throw(db_exception);
    
    void setByte(int param, char value);
    void setShort(int param, short value);
    void setInt(int param, int value);
    void setLongLong(int param, long long value);
    void setFloat(int param, float value);
    void setDouble(int param, double value);
    void setString(int param, std::string value);
    void setNull(int param);
};


/* db_result_set_sqlite3 */

class db_result_set_sqlite3 : public db_result_set
{
private:
    db_statement_sqlite3 *stmt;
    int step_rc;
    
public:
    db_result_set_sqlite3(db_statement_sqlite3 *stmt);
    ~db_result_set_sqlite3();

    bool next() throw(db_exception);
    
    bool isNull(int field);
    char getByte(int field);
    short getShort(int field);
    int getInt(int field);
    long long getLongLong(int field);
    float getFloat(int field);
    double getDouble(int field);
    std::string getString(int field);
};

#endif
