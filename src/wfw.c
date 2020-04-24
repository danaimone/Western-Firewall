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
#include <ws2tcpip.h>

/* Constants */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define MACSIZE 6


/* Globals  */
static char *conffile = STR(SYSCONFDIR) "/wfw.cfg";
static bool printusage = false;

/* Structs */
typedef struct EthernetFrame {
    char destMac[MACSIZE];
    char srcMac[MACSIZE];
    char type[2];
    char payload[1512];
} frame;

/* Helper Functions */
static void sendTo(int tapDevice, int uc, void *buffer, struct sockaddr_in bcaddress, hashtable *knownAddresses);

static void receiveUnicast(int tapDevice, int uc, void *buffer);

static void receiveBroadcast(int tapDevice, int bc, void *buffer, hashtable *knownAddresses);

static int macCmp(void *s1, void *s2);

static void freeKeys(void *key, void *val);

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
    } else if (printusage) {
        usage(argv[0], stdout);
    } else {
        hashtable conf = readconf(conffile);
        int tap = ensuretap(htstrfind(conf, DEVICE));
        int out = ensuresocket(ANYIF, ANYPORT);
        int in = ensuresocket(htstrfind(conf, BROADCAST),
                              htstrfind(conf, PORT));
        struct sockaddr_in
                bcaddr = makesockaddr(htstrfind(conf, BROADCAST),
                                      htstrfind(conf, PORT));

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
    static const char *OPTS = "hc:";

    bool parsed = true;

    char c = getopt(argc, argv, OPTS);
    while (c != -1) {
        switch (c) {
            case 'c':
                conffile = optarg;
                break;

            case 'h':
                printusage = true;
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
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
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
    int s = va_arg(ap, int);
    while (s != 0) {
        if (s > max)
            max = s;
        FD_SET(s, set);
        s = va_arg(ap, int);
    }
    va_end(ap);

    return max;
}


static void sendTo(int tapDevice, int uc, void *buffer, struct sockaddr_in bcaddress, hashtable *knownAddresses) {
    ssize_t rdct = read(tap, buffer, sizeof(frame));
    if (rdct < 0) {
        perror("read");
    } else {
        frame *tempBuf = buffer;
        struct sockaddr_in *out;
        if (hthaskey(*knownAddresses, tempBuf->destMac, MACSIZE)) {
            out = htfind(*knownAddresses, tempBuf->destMac, MACSIZE);
        } else {
            out = &bcaddress;
        }
        if (-1 == sendto(uc, buffer, rdct, 0, (struct sockaddr *) out, sizeof(*out))) {
            perror("sendto");
        }
    }
}

static void receiveUnicast(int tapDevice, int uc, void *buffer) {
    struct sockaddr_in receive;
    socklen_t receiveLength = sizeof(receive);
    ssize_t rdct = recvfrom(uc, buffer, sizeof(frame), 0, (struct sockaddr *) &receive, &receiveLength);

    if (rdct < 0) {
        perror("recvfrom");
    } else if (-1 == write(tapDevice, buffer, rdct)) {
        perror("write");
    }
}

static void receiveBroadcast(int tapDevice, int bc, void *buffer, hashtable *knownAddresses) {
    struct sockaddr_in receive;
    socklen_t receiveLength = sizeof(receive);
    ssize_t rdct = recvfrom(bc, buffer, sizeof(frame), 0, (struct sockaddr *) &receive, &receiveLength);

    if (rdct < 0) {

    } else {
        frame *tempBuffer = buffer;
        if (!hthaskey(*knownAddresses, tempBuffer->srcMac, MACSIZE)) {
            char *key = malloc(MACSIZE);
            memcpy(key, tempBuffer->srcMac, MACSIZE);
            struct sockaddr_in *receiveSocket = malloc(sizeof(struct sockaddr_in));
            memcpy(receiveSocket, &receive, sizeof(struct sockaddr_in));
            htinsert(*knownAddresses, key, MACSIZE, receiveSocket);
        }
        if (-1 == write(tapDevice, buffer, rdct)) {
            perror("write receiveBroadcast");
        }
    }
}

static int macCmp(void *s1, void *s2) {
    return memcmp(s1, s2, 6);
}

static void freeKeys(void *key, void *value) {
    free(key);
    free(value);
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int uc, int bc, struct sockaddr_in bcaddr) {
    fd_set rdset;

    int maxfd = mkfdset(&rdset, tap, bc, uc, 0);

    frame buffer;

    hashtable knownAddresses = htnew(32, macCmp, freeKeys);

    // use ethernet frame struct
    //  char buffer[BUFSZ];

    while (0 <= select(1 + maxfd, &rdset, NULL, NULL, NULL)) {
        if (FD_ISSET(tap, &rdset)) { // Tap device
            sendTo(tap, uc, &buffer, bcaddr, &knownAddresses);
        } else if (FD_ISSET(uc, &rdset)) { // UC send/receive
            receiveUnicast(tap, uc, &buffer);
        } else if (FD_ISSET(bc, &rdset)) { // Broadcast packets
            receiveBroadcast(tap, bc, &buffer, &knownAddresses);
        }

        maxfd = mkfdset(&rdset, tap, uc, 0);
    }

}
