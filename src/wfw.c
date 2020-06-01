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
static void
sendTap(int tap_device, int uc, struct sockaddr_in bc_address,
        hashtable *known_addresses, hashtable *known_connections);

static void
receiveBCorUC(int tap_device, int bc_or_uc, hashtable *known_addresses,
              hashtable *known_connections, hashtable *blacklist_connections,
              hashtable *conf);

static int
macCmp(void *s1, void *s2);

static int
connectionCmp(void *s1, void *s2);

static int
createTCPServerAndListen(char *address, char *port);

static void
freeKeys(void *key, void *val);


static void
insertAllowedConnection(hashtable *known_connections, uint16_t *src_port,
                        uint16_t
                        *dest_port, unsigned char *dest_addr);

static bool
isBroadcast(unsigned char *address);

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


/*
 * sendTap
 *
 * Sends packets out from the tap device. If the packet is an ipv6 packet with
 * a TCP segment and a set SYN bit, the connection request is inserted into a
 * hashtable for use in receiveBCorUC.
 */
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

/*
 * receiveBCorUC
 *
 * Listens on the tap device for incoming packets that are either directly
 * addressed (uc) or broadcasted (bc). If the packet is not an ipV6 packet and
 * a TCP segment that is a trusted connection, it is blocked.
 */
static void
receiveBCorUC(int tap_device, int bc_or_uc, hashtable *known_addresses,
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

                    if (!hthaskey(*known_addresses, buffer.src_mac, MACSIZE)) {
                        char *key = malloc(MACSIZE);
                        memcpy(key, buffer.src_mac, MACSIZE);

                        struct sockaddr_in *receive_socket = malloc(
                                sizeof(struct sockaddr_in));
                        memcpy(receive_socket, &receive,
                               sizeof(struct sockaddr_in));

                        if (!htinsert(*known_addresses, key, MACSIZE,
                                      receive_socket)) {
                            free(key);
                            free(receive_socket);
                            perror("htinsert receiveBroadcast");
                        }

                    } else {
                        void *value;
                        value = htfind(*known_addresses, buffer.src_mac,
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

/*
 * Helper function for comparing two addresses for hashtable creation
 */
static
int addrCmp(void *s1, void *s2) {
    return memcmp(s1, s2, 16);
}

/*
 * Helper function for comparing two values for hashtable creation
 */
static
int macCmp(void *s1, void *s2) {
    return memcmp(s1, s2, MACSIZE);
}

/*
 * Helper function to compare two values for allowedConnections hashtable
 * creation
 */
static
int connectionCmp(void *s1, void *s2) {
    return memcmp(s1, s2, sizeof(connectionKey));
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
//        read(client_sock, buffer, 16);
        shutdown(client_sock, SHUT_RD);
        close(client_sock);

        printf("Received blacklist: ");
        for (int i = 0; i < 16; ++i) {
            printf("%x", buffer[i]);
        }
        printf("\n\n");

        if (!hthaskey(*blacklist_connections, buffer, 16)) {
            unsigned char *blacklist_connection = malloc(16);
            memcpy(blacklist_connection, buffer, 16);
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
    char       *peersKey    = htstrfind(*conf, "PEERS");
    char       *peers       = strdup(peersKey);

    char *current_peer_server;
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

    hashtable known_addresses       = htnew(32, macCmp, freeKeys);
    hashtable known_connections     = htnew(32, connectionCmp, freeKeys);
    hashtable blacklist_connections = htnew(32, addrCmp, freeKeys);

    while (0 <= select(1 + maxfd, &rd_set, NULL, NULL, NULL)) {

        if (FD_ISSET(tap, &rd_set)) {
            sendTap(tap, uc, bc_addr, &known_addresses, &known_connections);
        } else if (FD_ISSET(uc, &rd_set)) {
            receiveBCorUC(tap, uc, &known_addresses, &known_connections,
                          &blacklist_connections, &conf);
        } else if (FD_ISSET(bc, &rd_set)) {
            receiveBCorUC(tap, bc, &known_addresses, &known_connections,
                          &blacklist_connections, &conf);
        } else if (FD_ISSET(tcp_server, &rd_set)) {
            receiveBlacklistedConnection(tcp_server, &blacklist_connections);
        }

        maxfd = mkFDSet(&rd_set, tap, bc, uc, tcp_server, 0);
    }
}

/* Connect to service/host
 *
 */

/***
 * Try to connect
 * This function will create a new socket and try to connect to the
 * socketaddr contained within the provided addrinfo structure.
 *
 * @param ai    An addr info structure.
 * @return      -1 or a socket connected to the sockaddr within ai.
 */
int tryConnect(struct addrinfo *ai) {
    int s = socket(ai->ai_family, ai->ai_socktype, 0);
    if (s != -1 && 0 != connect(s, ai->ai_addr, ai->ai_addrlen)) {
        close(s);
        s = -1;
    }

    return s;
}

static
int connectTo(const char *name, const char *service) {
    int s = -1;

    struct addrinfo hint;
    bzero(&hint, sizeof(struct addrinfo));
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_family   = AF_INET;

    struct addrinfo *info = NULL;

    if (0 == getaddrinfo(name, service, &hint, &info) &&
        NULL != info) {
        struct addrinfo *p = info;

        s = tryConnect(p);

        while (s == -1 && p->ai_next != NULL) {
            p = p->ai_next;
            s = tryConnect(p);
        }

    }
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

