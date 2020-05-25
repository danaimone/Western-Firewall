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
#define IPV6PACK  0x86dd


/* Globals  */
static char *confFile  = STR(SYSCONFDIR) "/wfw.cfg";
static bool printUsage = false;
static bool foreground = false;

/* Structs */
typedef struct EthernetFrame {
    unsigned char  destMac[MACSIZE];
    unsigned char  srcMac[MACSIZE];
    unsigned short type;
    unsigned char  payload[1500];
}           frame;

// @formatter:off
typedef struct Headerv6 {
    uint32_t version    : 4;
    uint32_t class      : 8;
    uint32_t flowLabel  : 20;

    uint32_t plen       : 16;
    uint32_t nextHeader : 8;
    uint32_t hop        : 8;

    unsigned char sourceAddr[16];
    unsigned char destAddr[16];

    uint8_t payload[];

} header_t;
// @formatter:on

/*
 * This struct represents allowed connections
 */
typedef struct ConnectionKey {
    uint16_t localPort;
    uint16_t remotePort;

    unsigned char remoteAddress[16];
} connectionKey;

// @formatter:off
typedef struct Segment {
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t sequenceNum;
    uint32_t ackNum;

    uint16_t            : 4;
    uint16_t headerSize : 4;
    uint16_t FIN        : 1;
    uint16_t SYN        : 1;
    uint16_t RST        : 1;
    uint16_t PSH        : 1;
    uint16_t ACK        : 1;
    uint16_t URG        : 1;
    uint16_t            : 2;

    uint16_t window;
    uint16_t checkSum;
    uint16_t urgent;
    uint32_t *options;
} tcpSegment;
// @formatter:on

/* Helper Functions */
static void
sendTap(int tapDevice, int uc, struct sockaddr_in bcaddress,
        hashtable *knownAddresses, hashtable *knownConnections);

static void
receiveBCorUC(int tapDevice, int bcOrUC, hashtable *knownAddresses,
              hashtable *knownConnections);

static int
macCmp(void *s1, void *s2);

static int
connectionCmp(void *s1, void *s2);

static void
freeKeys(void *key, void *val);


static void
insertAllowedConnection(hashtable *knownConnections, uint16_t *srcPort, uint16_t
*destPort, unsigned char *destAddr);

static bool
isBroadcast(unsigned char *address);

static bool
isTCPSegment(uint32_t nextHeader);

static bool
isAllowedConnection(frame buffer, hashtable *knownCookies);
/* Prototypes */

/* Parse Options
 * argc, argv   The command line
 * returns      true iff the command line is successfully parsed
 *
 * This function sets the otherwise immutable global variables (above).  
 */
static
bool parseoptions(int argc, char *argv[]);

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
int ensuretap(char *path);

/* Ensure Socket
 * localaddress   The IPv4 address to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local address and
 * the port number are strings.  
 */
static
int ensuresocket(char *localaddr, char *port);

/* Make Socket Address
 * address, port  The string representation of an IPv4 socket address.
 *
 * This is a convince routine to convert an address-port pair to an IPv4 socket
 * address.  
 */
static
struct sockaddr_in makesockaddr(char *address, char *port);

/* mkfdset
 * set    The fd_set to populate
 * ...    A list of file descriptors terminated with a zero.
 *
 * This function will clear the fd_set then populate it with the specified file
 * descriptors.  
 */
static
int mkfdset(fd_set *set, ...);

/* Bridge 
 * tap     The local tap device
 * bc      The network socket that receives broadcast packets.
 * uc     The network socket on with to send broadcast packets.
 * bcaddr  The broadcast address for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int bc, int uc, struct sockaddr_in bcaddr);

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

    if (!parseoptions(argc, argv)) {
        usage(argv[0], stderr);
        result = EXIT_FAILURE;
    } else if (printUsage) {
        usage(argv[0], stdout);
    } else {
        hashtable conf   = readconf(confFile);
        int       tap    = ensuretap(htstrfind(conf, DEVICE));
        int       out    = ensuresocket(ANYIF, ANYPORT);
        int       in     = ensuresocket(htstrfind(conf, BROADCAST),
                                        htstrfind(conf, PORT));
        struct sockaddr_in
                  bcaddr = makesockaddr(htstrfind(conf, BROADCAST),
                                        htstrfind(conf, PORT));

        if (!foreground)
            daemonize(conf);
        bridge(tap, in, out, bcaddr);

        close(in);
        close(out);
        close(tap);
        htfree(conf);
    }

    return result;
}


/* Parse Options
 *
 * see man 3 getopt
 */
static
bool parseoptions(int argc, char *argv[]) {
    static const char *OPTS  = "hc:f";

    bool              parsed = true;

    char c = getopt(argc, argv, OPTS);
    while (c != -1) {
        switch (c) {
            case 'c':
                confFile = optarg;
                break;

            case 'h':
                printUsage = true;
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
int ensuretap(char *path) {
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
int ensuresocket(char *localaddr, char *port) {
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

    struct sockaddr_in addr = makesockaddr(localaddr, port);
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
struct sockaddr_in makesockaddr(char *address, char *port) {
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_len    = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(atoi(port));
    inet_pton(AF_INET, address, &(addr.sin_addr));

    return addr;
}

/* mkfdset
 *
 * Note the use of va_list, va_arg, and va_end. 
 */
static
int mkfdset(fd_set *set, ...) {
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
sendTap(int tapDevice, int uc, struct sockaddr_in bcaddress,
        hashtable *knownAddresses, hashtable *knownConnections) {
    frame    buffer;
    header_t h;
    header_t *header = &h;
    ssize_t  rdct    = read(tapDevice, &buffer, sizeof(frame));


    if (rdct < 0) {
        perror("read");
    } else {
        struct sockaddr_in *out = &bcaddress;
        if (hthaskey(*knownAddresses, buffer.destMac, MACSIZE)) {
            out = htfind(*knownAddresses, buffer.destMac, MACSIZE);
        }

        if (htons(buffer.type) == IPV6PACK) {
            header = (header_t *) (&buffer)->payload;
            if (isTCPSegment(header->nextHeader)) {
                tcpSegment *segment = (tcpSegment *) header->payload;

                if (segment->SYN != 0) {
                    insertAllowedConnection(knownConnections,
                                            &segment->srcPort,
                                            &segment->destPort,
                                            &header->destAddr);
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
receiveBCorUC(int tapDevice, int bcOrUC, hashtable *knownAddresses,
              hashtable *knownConnections) {
    frame              buffer;
    struct sockaddr_in receive;
    socklen_t          receiveLength = sizeof(struct sockaddr_in);

    ssize_t rdct = recvfrom(bcOrUC, &buffer, sizeof(frame), 0,
                            (struct sockaddr *) &receive,
                            &receiveLength);

    if (rdct < 0) {
        perror("recvfrom receiveBroadcast");
    } else {
        if (isAllowedConnection(buffer, knownConnections)) {
            if (!isBroadcast(buffer.destMac)) {
                if (!hthaskey(*knownAddresses, buffer.srcMac, MACSIZE)) {

                    char *key = malloc(MACSIZE);
                    memcpy(key, buffer.srcMac, MACSIZE);

                    struct sockaddr_in *receiveSocket = malloc(
                            sizeof(struct sockaddr_in));
                    memcpy(receiveSocket, &receive,
                           sizeof(struct sockaddr_in));

                    if (!htinsert(*knownAddresses, key, MACSIZE,
                                  receiveSocket)) {
                        free(key);
                        free(receiveSocket);
                        perror("htinsert receiveBroadcast");
                    }
                } else {
                    void *value;
                    value = htfind(*knownAddresses, buffer.srcMac, MACSIZE);
                    memcpy(value, &receive, sizeof(struct sockaddr_in));
                }

                if (-1 == write(tapDevice, &buffer, rdct)) {
                    perror("write receiveBroadcast");
                }
            }
        }
    }
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

/*
 * Helper function to insert an allowed connection key into hashtable from
 * sendTap
 */
static void
insertAllowedConnection(hashtable *knownConnections, uint16_t *srcPort, uint16_t
*destPort, unsigned char *destAddr) {
    connectionKey *allowedConnection = malloc(sizeof(connectionKey));
    memcpy(&allowedConnection->localPort, srcPort, sizeof(uint16_t));
    memcpy(&allowedConnection->remotePort, destPort, sizeof(uint16_t));
    memcpy(&allowedConnection->remoteAddress, destAddr, 16);
    htinsert(*knownConnections, allowedConnection, sizeof(connectionKey), 0);
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
    static const char broadcastMac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const char multicastMac[] = {0x33, 0x33};

    return (memcmp(address, broadcastMac, 6) == 0 ||
            memcmp(address, multicastMac, 2) == 0);
}

/* isTCPSegment
 *
 * Returns true if an IPV6 packet contains a tcp segment, otherwise false
 */
static
bool isTCPSegment(uint32_t nextHeader) {
    return (nextHeader == TCPSEG);
}

/* isAllowedConnection
 *
 * Helper function to check if a given frame is an allowed connection based
 * on a hashtable check. Essentially, this function checks if the frame is
 * IPv6 as well as checks if the nextHeader has a TCP segment. This function
 * also returns true if it's an IPv4 packet or just a UDP segment.
 */
static bool
isAllowedConnection(frame buffer, hashtable *knownCookies) {
    bool allowed;
    if (htons(buffer.type) == IPV6PACK) {
        header_t *header = (header_t *) (&buffer)->payload;

        if (isTCPSegment(header->nextHeader)) {
            connectionKey *connection = malloc(sizeof(connectionKey));
            tcpSegment    *segment    = (tcpSegment *) header->payload;

            memcpy(&(connection)->localPort, &segment->destPort,
                   sizeof(uint16_t));
            memcpy(&(connection)->remotePort, &segment->srcPort,
                   sizeof(uint16_t));
            memcpy(&(connection)->remoteAddress, &header->sourceAddr, 16);
            allowed = hthaskey(*knownCookies, connection,
                               sizeof(connectionKey));

            free(connection);
        } else {
            allowed = true;
        }

    } else {
        allowed = true;
    }
    return allowed;
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int bc, int uc, struct sockaddr_in bcaddr) {
    fd_set rdset;

    int maxfd = mkfdset(&rdset, tap, bc, uc, 0);

    hashtable knownAddresses   = htnew(32, macCmp, freeKeys);
    hashtable knownConnections = htnew(32, connectionCmp, freeKeys);

    while (0 <= select(1 + maxfd, &rdset, NULL, NULL, NULL)) {

        if (FD_ISSET(tap, &rdset)) {
            sendTap(tap, uc, bcaddr, &knownAddresses, &knownConnections);
        } else if (FD_ISSET(uc, &rdset)) {
            receiveBCorUC(tap, uc, &knownAddresses, &knownConnections);
        } else if (FD_ISSET(bc, &rdset)) {
            receiveBCorUC(tap, bc, &knownAddresses, &knownConnections);
        }

        maxfd = mkfdset(&rdset, tap, bc, uc, 0);
    }
}

static
void daemonize(hashtable conf) {
    daemon(0, 0);
    if (hthasstrkey(conf, PID)) {
        FILE *pidfile = fopen(htstrfind(conf, "pidfile"),
                              "w");
        if (pidfile != NULL) {
            fprintf(pidfile, "%d\n", getpid());
            fclose(pidfile);
        }
    }
}

