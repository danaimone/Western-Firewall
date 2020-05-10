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

/* Globals  */
static char          *conffile     = STR(SYSCONFDIR) "/wfw.cfg";
static bool          printUsage    = false;
static bool          foreground    = false;

/* Structs */
typedef struct EthernetFrame {
    char  destMac[MACSIZE];
    char  srcMac[MACSIZE];
    short type;
    char  payload[1500];
}                    frame;

/* Helper Functions */
static void
sendTap(int tapDevice, int uc, struct sockaddr_in bcaddress,
        hashtable *knownAddresses);

static void receiveBCorUC(int tapDevice, int bc, hashtable *knownAddresses);

static int macCmp(void *s1, void *s2);

static void freeKeys(void *key, void *val);

static bool isBroadcast(char *address);


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
        hashtable conf   = readconf(conffile);
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
                conffile = optarg;
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


static void
sendTap(int tapDevice, int uc, struct sockaddr_in bcaddress,
        hashtable *knownAddresses) {
    frame   buffer;
    ssize_t rdct = read(tapDevice, &buffer, sizeof(frame));
    if (rdct < 0) {
        perror("read");
    } else {
        struct sockaddr_in *out = &bcaddress;
        if (hthaskey(*knownAddresses, buffer.destMac, MACSIZE)) {
            out = htfind(*knownAddresses, buffer.destMac, MACSIZE);
        }
        if (-1 == sendto(uc, &buffer, rdct, 0, (struct sockaddr *) out,
                         sizeof(*out))) {
            perror("sendto");
        }
    }
}

static void
receiveBCorUC(int tapDevice, int bc, hashtable *knownAddresses) {
    frame              buffer;

    struct sockaddr_in receive;
    socklen_t          receiveLength = sizeof(receive);

    ssize_t            rdct          = recvfrom(bc, &buffer, sizeof(frame), 0,
                                                (struct sockaddr *) &receive,
                                                &receiveLength);

    if (rdct < 0) {
        perror("recvfrom receiveBroadcast");
    } else {

        if(!isBroadcast(buffer.destMac)) {
            if (!hthaskey(*knownAddresses, buffer.srcMac, MACSIZE)) {

                char *key = malloc(MACSIZE);
                memcpy(key, buffer.srcMac, MACSIZE);

                struct sockaddr_in *receiveSocket = malloc(
                        sizeof(struct sockaddr_in));
                memcpy(receiveSocket, &receive, sizeof(struct sockaddr_in));

                if (!htinsert(*knownAddresses, key, MACSIZE, receiveSocket)) {
                    free(key);
                    free(receiveSocket);
                    perror("htinsert receiveBroadcast");
                }
            }
            else {
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

static int macCmp(void *s1, void *s2) {
    return memcmp(s1, s2, MACSIZE);
}

static void freeKeys(void *key, void *value) {
    free(key);
    free(value);
}

/*
 * In this function, we are checking the MAC address 33:33:... at the first two
 * bytes to see if the mac address being received in send is a broadcast. We
 * also set up an unsigned char array for the ff:ff:ff:ff:ff broadcast
 * address and check that as well.
 */
static bool isBroadcast(char *address) {
    static const char broadcastMac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const char multicastMac[] = {0x33, 0x33};

    return (memcmp(address, broadcastMac, 6) == 0 ||
            memcmp(address, multicastMac, 2) == 0);
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int bc, int uc, struct sockaddr_in bcaddr) {
    fd_set rdset;

    int       maxfd          = mkfdset(&rdset, tap, bc, uc, 0);
    hashtable knownAddresses = htnew(32, macCmp, freeKeys);

    while (0 <= select(1 + maxfd, &rdset, NULL, NULL,
                       NULL)) {

        if (FD_ISSET(tap, &rdset)) {
            sendTap(tap, uc, bcaddr, &knownAddresses);
        }
        else if (FD_ISSET(uc, &rdset)) {
            receiveBCorUC(tap, uc, &knownAddresses);
        }
        else if (FD_ISSET(bc, &rdset)) {
            receiveBCorUC(tap, bc, &knownAddresses);
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
