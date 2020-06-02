/*
 * Dan Aimone
 */
#include "conf.h"
#include "hash.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

/* Constants */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define MACSIZE   6
#define PID       "pidfile"
#define TCPSEG    6
#define PEERPORT  "14253"


/* Globals  */
static char           *conf_file   = STR(SYSCONFDIR) "/wfw.cfg";
static bool           print_usage  = false;
static bool           foreground   = false;
static unsigned short IPV6         = 0x86dd;
/* fd10:2020:c5c1:367:db8b:c15b:5eec:f0ca */
static unsigned char  local_ip[16] = {0xfd, 0x10, 0x20, 0x20,
                                      0xc5, 0xc1, 0x3, 0x67,
                                      0xdb, 0x8b, 0xc1, 0x5b,
                                      0x5e, 0xec, 0xf0, 0xca};
static unsigned char  local_mac[6] = {0xf2, 0x0b, 0xa4, 0xdf, 0x42, 0x01};

/* Structs */
typedef struct EthernetFrame {
    unsigned char  dest_mac[MACSIZE];
    unsigned char  src_mac[MACSIZE];
    unsigned short type;
    unsigned char  payload[1500];
}                     frame;

// @formatter:off
typedef struct Headerv6 {
    uint32_t version    : 4;
    uint32_t class      : 8;
    uint32_t flow_label : 20;

    uint32_t plen       : 16;
    uint32_t next_header: 8;
    uint32_t hop        : 8;

    unsigned char source_addr[16];
    unsigned char dest_addr[16];

    uint8_t payload[];

} header_t;
// @formatter:on

/*
 * This struct represents allowed connections
 */
typedef struct ConnectionKey {
    uint16_t local_port;
    uint16_t remote_port;

    unsigned char remote_address[16];
} connectionKey;

// @formatter:off
typedef struct Segment {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence_num;
    uint32_t ack_num;

    uint16_t            : 4;
    uint16_t header_size: 4;
    uint16_t FIN        : 1;
    uint16_t SYN        : 1;
    uint16_t RST        : 1;
    uint16_t PSH        : 1;
    uint16_t ACK        : 1;
    uint16_t URG        : 1;
    uint16_t            : 2;

    uint16_t window;
    uint16_t check_sum;
    uint16_t urgent;
    uint32_t *options;
} tcpSegment;

// @formatter:on

/* Helper Functions */

/***
 * Sends packets out from the tap device. If the packet is an ipv6 packet with
 * a TCP segment and a set SYN bit, the connection request is inserted into a
 * known_connections hashtable.
 *
 * @param tap_device the file descriptor of the tap device
 * @param uc file descriptor for unicast socket
 * @param bc_address the broadcast address
 * @param known_addresses known mac addresses hashtable
 * @param known_connections known connection keys hashtable
 */
static void
sendTap(int tap_device, int uc, struct sockaddr_in bc_address,
        hashtable *known_addresses, hashtable *known_connections);

/***
 * receive BC or UC
 *
 * Listens on the tap device for incoming unicast or broadcast packets.
 * If the packet is not an IPV6 packet and a TCP segment that is a known
 * connection, it is blocked.
 *
 * @param tap_device the file descriptor of the tap device
 * @param bc_or_uc the file descriptor of either the bc or uc socket
 * @param known_mac_addresses hashtable of known mac addresses
 * @param known_connections hashtable of known connection keys
 * @param blacklist_connections hashtable of blacklisted connections
 * @param conf the conf hashtable that contains peers for checking if allowed
 */
static void
receiveBCorUC(int tap_device, int bc_or_uc, hashtable *known_mac_addresses,
              hashtable *known_connections, hashtable *blacklist_connections,
              hashtable *conf);

/***
 * address comparison
 * Compares two ipv6 addresses for hashtable comparison
 * @param ipv6_1 an ipv6 address
 * @param ipv6_2 an ipv6 address
 * @return the bytes comparable between two addresses
 */
static
int addrCmp(void *ipv6_1, void *ipv6_2);

/***
 * mac address comparison
 * Compares two mac addresses for hashtable comparison
 * @param mac_1 a mac address
 * @param mac_2 a mac address
 * @return  the bytes comparable between the two mac addresses
 */
static int
macCmp(void *mac_1, void *mac_2);

/***
 * connection key comparison
 * Compares two connection keys for hashtable comparison
 * @param connection_key1 a connection key
 * @param connection_key2 a connection key
 * @return the bytes comparable between the two connection keys
 */
static int
connectionCmp(void *connection_key1, void *connection_key2);

/***
 * create TCP server and listen
 *
 * Setups a TCP server on the specified port and makes the necessary calls
 * to bind and listen. Makes use of makesockaddr to create a socket address.
 * @param address The address to bind the socket to
 * @param port The port to bind the socket to
 * @return A file descriptor for the created server
 */
static int
createTCPServerAndListen(char *address, char *port);

/***
 * free keys
 * Helper void pointer function to free the key value pairs of a hashtable.
 * @param key key to be freed
 * @param val value to be freed
 */
static void
freeKeys(void *key, void *val);

/***
 * Insert Allowed Connection
 * Inserts an allowed connection into the known connections hashtable if we
 * received a TCP SYN.
 *
 * @param known_connections the known connections hashtable to insert into
 * @param src_port the local port
 * @param dest_port the remotes port
 * @param dest_addr the receiver's destination IPV6 address
 */
static void
insertAllowedConnection(hashtable *known_connections, uint16_t *src_port,
                        uint16_t
                        *dest_port, unsigned char *dest_addr);

/***
 * is broadcast
 * Helper function to check if a mac address is a broadcast address
 * Checks both the ff:ff:ff:ff:ff broadcast as well as the 33:33:.... address
 *
 * @param address an 8 byte mac address to check
 * @return true if broadcast, false otherwise
 */
static bool
isBroadcast(unsigned char *address);

/***
 * is a tcp segment
 * Helper function to check if the next header can be identified as a TCP
 * segment
 * @param next_header header_t struct's next header field that has been
 * filled from a buffer payload
 *
 * @return true if the next header is TCP, false otherwise
 */
static bool
isTCPSegment(uint32_t next_header);

/* isAllowedConnection
 *
 * Helper function to check if a given frame is an allowed connection based
 * on a hashtable check. Essentially, this function checks if the frame is
 * IPv6 as well as checks if the next_header has a TCP segment. This function
 * also returns true if it's an IPv4 packet or just a UDP segment.
 *
 */
static bool
isAllowedConnection(frame buffer, hashtable *known_cookies, hashtable
*blacklist_connections, hashtable *conf);

/*** receiveBlacklistedConnection
 *
 * Receive a blacklisted connection from tcpServer
 *
 * @param sock the socket/FD of the tcpServer to receive
 * @param blacklist_connections a hashtable of blacklisted connections to add to
 */
static void
receiveBlacklistedConnection(int sock, hashtable *blacklist_connections);

/***
 * Send out a blacklist connection to a peer in conf over a tcpClient
 * @param blacklist_connection A blacklisted IPV6 address
 * @param conf The conf hashtable that contains peers to send to
 */
static void
sendBlacklistedConnection(unsigned char blacklist_connection[16], hashtable
*conf);

/***
 * Is Addressed Direct
 *
 * This function checks whether a frame is directly addressed to us.
 *
 * @param buffer the frame to check
 * @return true if addressed directly, false otherwise
 */
static
bool isAddressedDirect(frame buffer);

/* Prototypes */

/* Parse Options
 * argc, argv   The command line
 * returns      true iff the command line is successfully parsed
 *
 * This function sets the otherwise immutable global variables (above).  
 */
static
bool parseOptions(int argc, char **argv);

/* Usage
 * cmd   The name by which this program was invoked
 * file  The steam to which the usage statement is printed
 *
 * This function prints the simple usage statement.  This is typically invoked
 * if the user provides -h on the command line or the options don't parse.  
 */
static
void usage(char *cmd, FILE *file);

/* Ensure Tap
 * path     The full path to the tap device.
 * returns  If this function returns, it is the file descriptor for the tap
 *          device. 
 * 
 * This function tires to open the specified device for reading and writing.  If
 * that open fails, this function will report the error to stderr and exit the
 * program.   
 */
static
int ensureTap(char *path);

/* Ensure Socket
 * local_addr   The IPv4 address to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local address and
 * the port number are strings.  
 */
static
int ensureSocket(char *local_addr, char *port);

/* Make Socket Address
 * address, port  The string representation of an IPv4 socket address.
 *
 * This is a convince routine to convert an address-port pair to an IPv4 socket
 * address.  
 */
static
struct sockaddr_in makeSockAddr(char *address, char *port);

/* mkFDSet
 * set    The fd_set to populate
 * ...    A list of file descriptors terminated with a zero.
 *
 * This function will clear the fd_set then populate it with the specified file
 * descriptors.  
 */
static
int mkFDSet(fd_set *set, ...);

/* Bridge 
 * tap     The local tap device
 * bc      The network socket that receives broadcast packets.
 * uc     The network socket on with to send broadcast packets.
 * bc_addr  The broadcast address for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int bc, int uc, struct sockaddr_in bc_addr, int
tcp_server, hashtable conf);

/***
 * Connect to the specified host and service
 * @param name  The host name or address to connect to.
 * @param service   The service name or service to connect to.
 * @return      -1 or a connected socket.
 *
 * Note: a non-negative return is a newly created socket that shall be closed.
 */
static
int connectTo(const char *name, const char *service);

/* Daemonize
 * 
 * Make this process a background, daemon process.
 */
static
void daemonize(hashtable conf);

/* Main
 * 
 * Mostly, main parses the command line, the conf file, creates the necessary
 * structures and then calls bridge.  Bridge is where the real work is done. 
 */
int main(int argc, char *argv[]) {
    int result = EXIT_SUCCESS;

    if (!parseOptions(argc, argv)) {
        usage(argv[0], stderr);
        result = EXIT_FAILURE;
    } else if (print_usage) {
        usage(argv[0], stdout);
    } else {
        hashtable conf       = readconf(conf_file);
        int       tap        = ensureTap(htstrfind(conf, DEVICE));
        int       out        = ensureSocket(ANYIF, ANYPORT);
        int       in         = ensureSocket(htstrfind(conf, BROADCAST),
                                            htstrfind(conf, PORT));
        int       tcp_server = createTCPServerAndListen(ANYIF, PEERPORT);
        struct sockaddr_in
                  bcaddr     = makeSockAddr(htstrfind(conf, BROADCAST),
                                            htstrfind(conf, PORT));

        if (!foreground)
            daemonize(conf);
        bridge(tap, in, out, bcaddr, tcp_server, conf);

        close(in);
        close(out);
        close(tap);
        close(tcp_server);
        htfree(conf);
    }

    return result;
}


/* Parse Options
 *
 * see man 3 getopt
 */
static
bool parseOptions(int argc, char **argv) {
    static const char *OPTS  = "hc:f";

    bool              parsed = true;

    char c = getopt(argc, argv, OPTS);
    while (c != -1) {
        switch (c) {
            case 'c':
                conf_file = optarg;
                break;

            case 'h':
                print_usage = true;
                break;

            case 'f':
                foreground = true;
                break;

            case '?':
                parsed = false;
                break;
        }

        c = parsed ? getopt(argc, argv, OPTS) : -1;
    }

    if (parsed) {
        argc -= optind;
        argv += optind;
    }

    return parsed;
}

/* Print Usage Statement
 *
 */
static
void usage(char *cmd, FILE *file) {
    fprintf(file, "Usage: %s -c file.cfg [-h]\n", cmd);
}

/* Ensure Tap device is open.
 *
 */
static
int ensureTap(char *path) {
    int fd = open(path, O_RDWR | O_NOSIGPIPE);
    if (-1 == fd) {
        perror("open");
        fprintf(stderr, "Failed to open device %s\n", path);
        exit(EXIT_FAILURE);
    }
    return fd;
}

/* Ensure socket
 *
 * Note the use of atoi, htons, and inet_pton. 
 */
static
int ensureSocket(char *local_addr, char *port) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (-1 == sock) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int bcast = 1;
    if (-1 == setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                         &bcast, sizeof(bcast))) {
        perror("setsockopt(broadcast)");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = makeSockAddr(local_addr, port);
    if (0 != bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind");
        char buf[80];
        fprintf(stderr,
                "failed to bind to %s\n",
                inet_ntop(AF_INET, &(addr.sin_addr), buf, 80));
        exit(EXIT_FAILURE);
    }

    return sock;
}

/* Make Sock Addr
 * 
 * Note the use of inet_pton and htons.
 */
static
struct sockaddr_in makeSockAddr(char *address, char *port) {
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_len    = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(atoi(port));
    inet_pton(AF_INET, address, &(addr.sin_addr));

    return addr;
}

/* mkFDSet
 *
 * Note the use of va_list, va_arg, and va_end. 
 */
static
int mkFDSet(fd_set *set, ...) {
    int max = 0;

    FD_ZERO(set);

    va_list ap;
    va_start(ap, set);
    int s = va_arg(ap,
                   int);
    while (s != 0) {
        if (s > max)
            max = s;
        FD_SET(s, set);
        s = va_arg(ap,
                   int);
    }
    va_end(ap);

    return max;
}


static void
sendTap(int tap_device, int uc, struct sockaddr_in bc_address,
        hashtable *known_addresses, hashtable *known_connections) {
    frame    buffer;
    header_t h;
    header_t *header = &h;
    ssize_t  rdct    = read(tap_device, &buffer, sizeof(frame));


    if (rdct < 0) {
        perror("read");
    } else {
        struct sockaddr_in *out = &bc_address;
        if (hthaskey(*known_addresses, buffer.dest_mac, MACSIZE)) {
            out = htfind(*known_addresses, buffer.dest_mac, MACSIZE);
        }

        unsigned short type = htons((&buffer)->type);
        if (memcmp(&type, &IPV6, 2) == 0) {
            header = (header_t *) (&buffer)->payload;
            if (isTCPSegment(header->next_header)) {
                tcpSegment *segment = (tcpSegment *) header->payload;

                if (segment->SYN != 0) {
                    insertAllowedConnection(known_connections,
                                            &segment->src_port,
                                            &segment->dest_port,
                                            header->dest_addr);
                }
            }
        }


        if (-1 == sendto(uc, &buffer, rdct, 0, (struct sockaddr *) out,
                         sizeof(*out))) {
            perror("sendto");
        }
    }
}

static void
receiveBCorUC(int tap_device, int bc_or_uc, hashtable *known_mac_addresses,
              hashtable *known_connections, hashtable *blacklist_connections,
              hashtable *conf) {
    frame              buffer;
    struct sockaddr_in receive;
    socklen_t          receive_length = sizeof(struct sockaddr_in);

    ssize_t rdct = recvfrom(bc_or_uc, &buffer, sizeof(frame), 0,
                            (struct sockaddr *) &receive,
                            &receive_length);

    if (rdct < 0) {
        perror("recvfrom receiveBroadcast");
    } else {
        if (isAddressedDirect(buffer)) {
            if (isAllowedConnection(buffer, known_connections,
                                    blacklist_connections, conf)) {

                if (!isBroadcast(buffer.src_mac)) {

                    if (!hthaskey(*known_mac_addresses, buffer.src_mac,
                                  MACSIZE)) {
                        char *key = malloc(MACSIZE);
                        memcpy(key, buffer.src_mac, MACSIZE);

                        struct sockaddr_in *receive_socket = malloc(
                                sizeof(struct sockaddr_in));
                        memcpy(receive_socket, &receive,
                               sizeof(struct sockaddr_in));

                        if (!htinsert(*known_mac_addresses, key, MACSIZE,
                                      receive_socket)) {
                            free(key);
                            free(receive_socket);
                            perror("htinsert receiveBroadcast");
                        }

                    } else {
                        void *value;
                        value = htfind(*known_mac_addresses, buffer.src_mac,
                                       MACSIZE);
                        memcpy(value, &receive, sizeof(struct sockaddr_in));
                    }

                    if (-1 == write(tap_device, &buffer, rdct)) {
                        perror("write receiveBroadcast");
                    }
                }
            }
        }
    }
}

static
int addrCmp(void *ipv6_1, void *ipv6_2) {
    return memcmp(ipv6_1, ipv6_2, 16);
}

static
int macCmp(void *mac_1, void *mac_2) {
    return memcmp(mac_1, mac_2, MACSIZE);
}

static
int connectionCmp(void *connection_key1, void *connection_key2) {
    return memcmp(connection_key1, connection_key2, sizeof(connectionKey));
}

static int
createTCPServerAndListen(char *localAddress, char *port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sock) {
        perror("createTCPServerAndListen sock");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address = makeSockAddr(localAddress, port);
    if (0 != bind(sock, (struct sockaddr *) &address, sizeof(address))) {
        perror("createTCPServerAndListen bind");
        exit(EXIT_FAILURE);
    }

    if (-1 == listen(sock, 1))
        perror("createTCPServerAndListen listen");

    return sock;
}


/*
 * Helper function to insert an allowed connection key into hashtable from
 * sendTap
 */
static void
insertAllowedConnection(hashtable *known_connections, uint16_t *src_port,
                        uint16_t
                        *dest_port, unsigned char *dest_addr) {
    connectionKey *allowed_connection = malloc(sizeof(connectionKey));
    memcpy(&allowed_connection->local_port, src_port, sizeof(uint16_t));
    memcpy(&allowed_connection->remote_port, dest_port, sizeof(uint16_t));
    memcpy(&allowed_connection->remote_address, dest_addr, 16);
    htinsert(*known_connections, allowed_connection, sizeof(connectionKey), 0);
}

/*
 * Helper void pointer function to free the key value pair of the hashtable
 */
static
void freeKeys(void *key, void *value) {
    free(key);
    free(value);
}

/*
 * In this function, we are checking the MAC address 33:33:... at the first two
 * bytes to see if the mac address being received in send is a broadcast. We
 * also set up an unsigned char array for the ff:ff:ff:ff:ff broadcast
 * address and check that as well.
 */
static
bool isBroadcast(unsigned char *address) {
    static const char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const char multicast_mac[] = {0x33, 0x33};

    return (memcmp(address, broadcast_mac, 6) == 0 ||
            memcmp(address, multicast_mac, 2) == 0);
}

/* isTCPSegment
 *
 * Returns true if an IPV6 packet contains a tcp segment, otherwise false
 */
static
bool isTCPSegment(uint32_t next_header) {
    return (next_header == TCPSEG);
}

static bool
isAllowedConnection(frame buffer, hashtable *known_cookies, hashtable
*blacklist_connections, hashtable *conf) {
    bool     allowed = false;
    header_t *header = (header_t *) (&buffer)->payload;

    if (!hthaskey(*blacklist_connections, header->source_addr, 16)) {
        unsigned short type = htons((&buffer)->type);
        if (memcmp(&type, &IPV6, 2) == 0 &&
            isTCPSegment(header->next_header)) {
            connectionKey connection;
            tcpSegment    *segment = (tcpSegment *) header->payload;
            memcpy(&connection.local_port, &segment->dest_port,
                   sizeof(uint16_t));
            memcpy(&connection.remote_port, &segment->src_port,
                   sizeof(uint16_t));
            memcpy(&connection.remote_address, &header->source_addr, 16);

            if (hthaskey(*known_cookies, &connection,
                         sizeof(connectionKey))) {
                allowed = true;
            } else {
                unsigned char *connection_addr = malloc(16);
                memcpy(connection_addr, header->source_addr, 16);
                htinsert(*blacklist_connections, connection_addr, 16, NULL);

                sendBlacklistedConnection(header->source_addr, conf);
            }

        } else {
            allowed = true;
        }
    }
    return allowed;
}

/*** receiveBlacklistedConnection
 *
 * Receive a blacklisted connection from tcpServer
 *
 * @param sock the socket/FD of the tcpServer to receive
 * @param blacklist_connections a hashtable of blacklisted connections to add to
 */
static void
receiveBlacklistedConnection(int sock, hashtable *blacklist_connections) {
    unsigned char buffer[16];
    socklen_t     length      = sizeof(struct sockaddr_in);
    int           client_sock = accept(sock, (struct sockaddr *) &client_sock,
                                       &length);

    if (client_sock != -1) {
        while (0 < read(client_sock, buffer, 16)) {}
        shutdown(client_sock, SHUT_RD);
        close(client_sock);

        printf("Received blacklist: ");
        for (int i = 0; i < 16; ++i) {
            printf("%x", buffer[i]);
        }
        printf("\n\n");

        if (!hthaskey(*blacklist_connections, buffer, 16)) {
            unsigned char *blacklist_connection = malloc(16);
            memcpy(blacklist_connection, &buffer, 16);
            printf("Received and wrote blacklist: ");
            for (int i = 0; i < 16; ++i) {
                printf("%x", blacklist_connection[i]);
            }
            printf("\n\n");
            htinsert(*blacklist_connections, blacklist_connection, 16, NULL);
        }
    } else {
        printf("Blacklisted connection was not accepted on receive.\n");
    }
}

/* Sends a blacklisted connection to peers over TCP client using DNS hostname
 *
 */
static void
sendBlacklistedConnection(unsigned char blacklist_connection[16], hashtable
*conf) {
    char *peersKey          = htstrfind(*conf, "PEERS");
    char *peers             = strdup(peersKey);

    char       *current_peer_server;
    const char delimiter[2] = ",";
    current_peer_server = strtok(peers, delimiter);

    while (current_peer_server != NULL) {
        printf("Current peer client: %s\n", current_peer_server);
        int peer_socket = connectTo(current_peer_server, PEERPORT);

        printf("Connected to %s\n", current_peer_server);
        write(peer_socket, blacklist_connection, 16);
        printf("Sent ");
        for (int i = 0; i < 16; ++i) {
            printf("%x", blacklist_connection[i]);
        }
        printf(" to %s", current_peer_server);
        printf("\n \n");

        shutdown(peer_socket, SHUT_RDWR);
        close(peer_socket);

        current_peer_server = strtok(NULL, delimiter);
    }
}

static
bool isAddressedDirect(frame buffer) {
    bool           ret     = false;
    unsigned short type    = htons((&buffer)->type);
    header_t       *header = (header_t *) (&buffer)->payload;

    if ((memcmp(&type, &IPV6, 2) == 0) && memcmp(header->dest_addr, &local_ip,
                                                 16) == 0) {
        ret = true;
    }
    return ret;
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int bc, int uc, struct sockaddr_in bc_addr, int
tcp_server, hashtable conf) {
    fd_set rd_set;

    int maxfd = mkFDSet(&rd_set, tap, bc, uc, tcp_server, 0);

    hashtable known_mac_addresses   = htnew(32, macCmp, freeKeys);
    hashtable known_connections     = htnew(32, connectionCmp, freeKeys);
    hashtable blacklist_connections = htnew(32, addrCmp, freeKeys);

    while (0 <= select(1 + maxfd, &rd_set, NULL, NULL, NULL)) {

        if (FD_ISSET(tap, &rd_set)) {
            sendTap(tap, uc, bc_addr, &known_mac_addresses, &known_connections);
        } else if (FD_ISSET(uc, &rd_set)) {
            receiveBCorUC(tap, uc, &known_mac_addresses, &known_connections,
                          &blacklist_connections, &conf);
        } else if (FD_ISSET(bc, &rd_set)) {
            receiveBCorUC(tap, bc, &known_mac_addresses, &known_connections,
                          &blacklist_connections, &conf);
        } else if (FD_ISSET(tcp_server, &rd_set)) {
            receiveBlacklistedConnection(tcp_server, &blacklist_connections);
        }

        maxfd = mkFDSet(&rd_set, tap, bc, uc, tcp_server, 0);
    }
}

/* Connect To the specified host and service
 *
 */

/* Timed Connect
 *
 * This function tries to connect to the specified sockaddr if a connection can
 * be made within tval time.
 *
 * The socket is temporarily put in non-blocking mode, a connection is tarted,
 * and select is used to do the actual timeout logic.
 */
static
int timedConnect(int              sock,
                 struct sockaddr* addr,
                 socklen_t        leng,
                 struct timeval   tval) {

    int status = -1;

    int ostate = fcntl(sock, F_GETFL, NULL);
    int nstate = ostate | O_NONBLOCK;

    if( ostate < 0 || fcntl(sock, F_SETFL, nstate) < 0) {
        perror("fcntl");
    }
    else {
        status = connect(sock, addr, leng);
        if(status < 0 && errno == EINPROGRESS) {
            fd_set wrset;
            int maxfd = mkfdset(&wrset, sock, 0);
            status = (0 < select(maxfd+1, NULL, &wrset, NULL, &tval) ?
                      0 : -1);
        }

        ostate = fcntl(sock, F_GETFL, NULL);
        nstate = ostate & ~O_NONBLOCK;
        if(ostate < 0 || fcntl(sock, F_SETFL, &nstate) < 0) {
            perror("fcntl");
        }
    }


    return status;

}

/* Try to connect
 * ai       An addrinfo structure.
 * returns  -1 or a socket connected to the sockaddr within ai.
 *
 * This function will create a new socket and try to connect to the socketaddr
 * contained within the provided addrinfo structure.
 */
static
int tryConnect(struct addrinfo* ai) {
    assert(ai);
    struct timeval tv = {1,0};
    int s = socket(ai->ai_family, ai->ai_socktype, 0);
    if(s != -1 && 0 != timedConnect(s, ai->ai_addr, ai->ai_addrlen, tv)) {
        close(s);
        s = -1;
    }

    return s;
}


static
int connectTo(const char* name, const char* svc) {
    assert(name != NULL);
    assert(svc  != NULL);

    int s = -1;

    struct addrinfo hint;
    bzero(&hint, sizeof(struct addrinfo));
    hint.ai_socktype = SOCK_STREAM;

    struct addrinfo* info = NULL;

    if (0    == getaddrinfo(name, svc, &hint, &info) &&
        NULL != info ) {

        struct addrinfo* p = info;

        s = tryConnect(p);
        while (s == -1 && p->ai_next != NULL) {
            p = p->ai_next;
            s = tryConnect(p);
        }
    }

    freeaddrinfo(info);
    return s;
}

static
void daemonize(hashtable conf) {
    daemon(0, 0);
    if (hthasstrkey(conf, PID)) {
        FILE *pid_file = fopen(htstrfind(conf, PID),
                               "w");
        if (pid_file != NULL) {
            fprintf(pid_file, "%d\n", getpid());
            fclose(pid_file);
        }
    }
}

