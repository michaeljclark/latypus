//
//  socket_unix.h
//

#ifndef socket_unix_h
#define socket_unix_h

/* unix socketpair
 *
 * used for inter thread/process ipc
 */

enum unix_socketpair_user
{
    unix_socketpair_owner,
    unix_socketpair_client,
};

struct unix_socketpair
{
    generic_socket owner;
    generic_socket client;
    
    unix_socketpair(int buf_size);
    
    generic_socket& owner_sock() { return owner; }
    generic_socket& client_sock() { return client; }
    
    io_result send_message(unix_socketpair_user user, void *buffer, size_t length);
    io_result recv_message(unix_socketpair_user user, void *buffer, size_t length);
};

#endif
