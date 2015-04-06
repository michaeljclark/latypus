//
//  db_mysql.h
//

#ifndef db_mysql_h
#define db_mysql_h

struct st_mysql;
struct st_mysql_stmt;
struct st_mysql_bind;

typedef char my_bool;

typedef struct st_mysql MYSQL;
typedef struct st_mysql_stmt MYSQL_STMT;
typedef struct st_mysql_bind MYSQL_BIND;

class db_driver_mysql;
class db_connection_uri_mysql;
class db_connection_mysql;
class db_statement_mysql;
class db_result_set_mysql;


/* db_driver_mysql */

class db_driver_mysql : public db_driver
{
public:
    static db_driver_mysql driver;
    
    db_driver_mysql();
    ~db_driver_mysql();
    
    std::vector<std::string> getDriverNames();
    db_connection_ptr createConnection(const std::string &db_uri, const std::string &username, const std::string &password) throw(db_exception);
};


/* db_connection_uri_mysql */

class db_connection_uri_mysql : public db_connection_uri
{
public:
    std::string driver;
    std::string host;
    int port;
    std::string db_name;
    std::string options;
    
    db_connection_uri_mysql(const std::string &db_uri, const std::string &username, const std::string &password);

    void decode() throw(db_exception);
    std::string to_string() const;
};


/* db_metadata_mysql */

class db_metadata_mysql : public db_metadata
{
private:
    db_connection_mysql *conn;
    
public:
    db_metadata_mysql(db_connection_mysql *conn);
    
    std::vector<std::string> getTableNames(std::string schema_name) throw(db_exception);
    db_table_definition_ptr getTableDefinition(std::string table_name, std::string schema_name) throw(db_exception);
};


/* db_connection_mysql */

class db_connection_mysql : public db_connection
{
private:
    friend class db_statement_mysql;
    friend class db_result_set_mysql;
    friend class db_metadata_mysql;
    
    MYSQL *mysql;
    bool autocommit;
    
public:
    db_connection_mysql(db_connection_uri_ptr conn_info);
    ~db_connection_mysql();

    void connect() throw(db_exception);
    bool getAutoCommit() throw(db_exception);
    void setAutoCommit(bool autocommit) throw(db_exception);
    void commit() throw(db_exception);
    void rollback() throw(db_exception);
    db_metadata_ptr getMetaData();
    db_statement_ptr prepareStatement(std::string sql) throw(db_exception);
};


/* db_statement_mysql */

class db_statement_mysql : public db_statement
{
private:
    friend class db_result_set_mysql;
    
    db_connection_mysql *conn;
    MYSQL_STMT *stmt;
    std::vector<MYSQL_BIND> fields;
    std::vector<MYSQL_BIND> params;
    std::vector<std::unique_ptr<unsigned char>> paramdata;
    std::vector<std::pair<size_t,size_t>> field_size_offset;
    std::unique_ptr<unsigned char> rowdata;
    size_t rowdata_size;
    db_field_metadata_list field_metadata;
    long long rows_changed;
    
public:
    db_statement_mysql(db_connection_mysql *conn, const std::string sql);
    ~db_statement_mysql();

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


/* db_result_set_mysql */

class db_result_set_mysql : public db_result_set
{
private:
    db_statement_mysql *stmt;
    
    struct RowData {
        unsigned long length;
        my_bool is_null;
        my_bool error;
    };
    
    RowData getRowData(int field)
    {
        size_t size = stmt->field_size_offset[field].first;
        size_t offset = stmt->field_size_offset[field].second;
        unsigned char *data_start = stmt->rowdata.get() + offset;
        unsigned char *data_end = data_start + size;
        my_bool is_null = *(my_bool*)(data_end - sizeof(unsigned long) - sizeof(my_bool) - sizeof(my_bool));
        my_bool error = *(my_bool*)(data_end - sizeof(unsigned long) - sizeof(my_bool));
        unsigned long length = *(unsigned long*)(data_end - sizeof(unsigned long));
        return RowData{length, is_null, error};
    }

    template <typename T> T* getRowPtr(int field)
    {
        size_t offset = stmt->field_size_offset[field].second;
        unsigned char *data_start = stmt->rowdata.get() + offset;
        return (T*)data_start;
    }

public:
    db_result_set_mysql(db_statement_mysql *stmt);
    ~db_result_set_mysql();

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
