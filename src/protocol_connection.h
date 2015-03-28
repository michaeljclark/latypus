//
//  protocol_connection.h
//

#ifndef protocol_connection_h
#define protocol_connection_h


/* protocol_connection_state */

template <typename ProtocolConnection>
struct protocol_connection_state
{
    typedef std::vector<ProtocolConnection>         connection_table;
    typedef std::vector<ProtocolConnection*>        connection_list;
    typedef std::deque<ProtocolConnection*>         connection_queue;
    typedef std::map<std::string,connection_queue>  connection_host_map;
    typedef std::pair<std::string,connection_queue> connection_host_entry;
    
    std::mutex                                      connections_mutex;
    connection_table                                connections_all;
    connection_list                                 connections_free;
    connection_host_map                             connections_host_map;
    
    void init(protocol_engine_delegate *delegate, int num_connections)
    {
        // initialize connection table
        connections_all.resize(num_connections);
        connections_free.resize(num_connections);
        for (int i = 0; i < num_connections; i++) {
            connections_all[i].conn.set_id(i);
            connections_all[i].init(delegate);
            connections_free[i] = &connections_all[i];
        }
    }
    
    ProtocolConnection* new_connection(protocol_engine_delegate *delegate)
    {
        ProtocolConnection *conn = nullptr;
        connections_mutex.lock();
        if (connections_free.size() > 0) {
            conn = connections_free.back();
            connections_free.pop_back();
        }
        connections_mutex.unlock();
        if (conn) {
            conn->init(delegate);
        }
        return conn;
    }
    
    ProtocolConnection* get_connection(protocol_engine_delegate *delegate, int conn_id)
    {
        return &connections_all[conn_id];
    }
    
    void free_connection(protocol_engine_delegate *delegate, protocol_object *obj)
    {
        auto conn = static_cast<ProtocolConnection*>(obj);
        conn->free(delegate);
        connections_mutex.lock();
        connections_free.push_back(conn);
        connections_mutex.unlock();
    }
    
    void abort_connection(protocol_engine_delegate *delegate, protocol_object *obj)
    {
        auto conn = static_cast<ProtocolConnection*>(obj);
        conn->conn.close();
        free_connection(delegate, conn);
    }
    
    void close_connection(protocol_engine_delegate *delegate, protocol_object *obj)
    {
        auto conn = static_cast<ProtocolConnection*>(obj);
        conn->conn.close();
        free_connection(delegate, conn);
    }
};

#endif
