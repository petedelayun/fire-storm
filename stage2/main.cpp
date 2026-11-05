#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <vector>
#include <map>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <string>
#include <algorithm>
#include <iterator>

const char *const LISTEN_PORT = "5733";
const char *const FORWARD_HOST = "localhost";
const int TCP_PORT = 5744;
const int MONITOR_PORT = 5745;
const int UDP_PORT = 5746;
const int BACKLOG = 10;
const size_t RECV_BUFFER_SIZE = 4096;

const unsigned char MAGIC[4] = {'C','T','F','S'};
const unsigned char ZERO_PADDING[3] = {0, 0, 0};
const size_t CTFS_HEADER_LEN = 16;
const size_t MAX_PAYLOAD = 512;

const size_t ETH_LEN = sizeof(struct ether_header);
const size_t IP_MIN_LEN = sizeof(struct ip);

const unsigned char ATTACKER_PREFIXES[][3] = {
    {0x00, 0x0C, 0x29}, {0x00, 0x50, 0x56}, {0x00, 0x1C, 0x14}
};
const unsigned char MONITOR_PREFIXES[][3] = {
    {0x00, 0x1A, 0xA0}, {0x00, 0x1E, 0xC9}, {0x00, 0x15, 0x5D}
};

std::vector<int> route_frame(const unsigned char *frame, size_t len)
{
    std::vector<int> ports;
    struct ether_header eth;
    struct ip iph;

    if (len < sizeof eth + sizeof iph) return ports;    // too short

    memcpy(&eth, frame, sizeof eth);                    // 14 bytes
    memcpy(&iph, frame + sizeof eth, sizeof iph);       // 20 bytes

    for (const auto &prefix : MONITOR_PREFIXES) {
        if (memcmp(eth.ether_dhost, prefix, 3) == 0) {
            ports.push_back(MONITOR_PORT);
            break;
        }
    }

    for (const auto &prefix : ATTACKER_PREFIXES) {
        if (memcmp(eth.ether_shost, prefix, 3) == 0) {
            return ports;
        }
    }

    if (ntohs(eth.ether_type) != ETHERTYPE_IP) return ports;  // not IP

    int protocol = iph.ip_p;
    if (protocol == IPPROTO_TCP) {
        ports.push_back(TCP_PORT);
    } else if (protocol == IPPROTO_UDP) {
        ports.push_back(UDP_PORT);
    }
    
    return ports;
}

int create_listener()
{
    struct addrinfo hints, *results, *ai;
    int listening_fd = -1;
    int reuse = 1;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;          // IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP
    hints.ai_flags = AI_PASSIVE;        // address for bind()

    status = getaddrinfo(NULL, LISTEN_PORT, &hints, &results);
    if (status != 0) {
        fprintf(stderr, "server: getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    for(ai = results; ai != NULL; ai = ai->ai_next) {
        listening_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (listening_fd == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(listening_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                sizeof reuse) == -1) {
            perror("server: setsockopt");
            close(listening_fd);
            continue;
        }

        if (bind(listening_fd, ai->ai_addr, ai->ai_addrlen) == -1) {
            perror("server: bind");
            close(listening_fd);
            listening_fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(results);
    
    if (ai == NULL)  {
        fprintf(stderr, "server: error: could not bind to port %s\n", LISTEN_PORT);
        return -1;
    }

    if (listen(listening_fd, BACKLOG) == -1) {
        perror("server: listen");
        close(listening_fd);
        return -1;
    }

    return listening_fd;
}

int connect_outbound(std::map<int, int> &outbound_fds, int port)
{
    if (outbound_fds.count(port)) {
        if (outbound_fds[port] != -1) return outbound_fds[port];
    }

    struct addrinfo hints, *results, *ai;
    int outbound_fd = -1;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;          // IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP

    std::string port_str = std::to_string(port);
    status = getaddrinfo(FORWARD_HOST, port_str.c_str(), &hints, &results);
    if (status != 0) {
        fprintf(stderr, "client: getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    for (ai = results; ai != NULL; ai = ai->ai_next) {
        outbound_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (outbound_fd == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(outbound_fd, ai->ai_addr, ai->ai_addrlen) == -1) {
            perror("client: connect");
            close(outbound_fd);
            outbound_fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(results);

    if (ai == NULL) {
        fprintf(stderr, "client: error: could not connect to port %s\n", port_str.c_str());
        return -1;
    }

    outbound_fds[port] = outbound_fd;

    return outbound_fd;
}

bool send_all(int outbound_fd, const unsigned char *data, size_t len)
{
    if (len == 0) return true;
    if (outbound_fd == -1) return false;

    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(outbound_fd, data + total_sent, len - total_sent, 0);
        if (sent == -1) {
            if (errno == EINTR) continue;
            perror("client: send");
            return false;
        }

        total_sent += sent;
    }

    return true;
}

void build_pdf(std::map<uint8_t, std::map<uint16_t, std::vector<unsigned char>>> &files)
{
    for (auto &[file_id, chunks] : files) {
        if (!chunks.empty() && (size_t)chunks.rbegin()->first + 1 != chunks.size()) {
            fprintf(stderr, "warning: file %u missing a sequence, the PDF may be incomplete\n", file_id);
        }

        std::string name = std::to_string(file_id) + ".pdf";
        FILE *f = fopen(name.c_str(), "wb");          // "wb": binary mode
        if (!f) perror(name.c_str());
        else {
            for (auto &kv : chunks)                   // a map iterates in key order: 0, 1, 2...
            {
                if (!kv.second.empty()) {
                    fwrite(kv.second.data(), 1, kv.second.size(), f);
                }        
            }
            fclose(f);
        }
    }

}

bool has_valid_checksum(const unsigned char *pkt, size_t len)
{
    if (len < CTFS_HEADER_LEN) return false;

    uint32_t checksum;
    memcpy(&checksum, pkt + 9, 4);
 
    std::vector<unsigned char> copy(pkt, pkt + len);
    std::copy(std::begin(MAGIC), std::end(MAGIC), copy.begin() + 9);
    copy.resize((copy.size() + 3) / 4 * 4, 0);

    uint32_t sum = 0;
    for (size_t i = 0; i < copy.size(); i += 4) {
        uint32_t word;
        memcpy(&word, &copy[i], 4);
        sum += ntohl(word);
        sum = (sum << 1) | (sum >> 31);
    }

    return sum == ntohl(checksum);
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "usage: %s [--verify-checksum]\n", prog);
}

int main(int argc, char *argv[])
{
    bool verify_checksum = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verify-checksum") == 0) {
            verify_checksum = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE to prevent crashes on send to closed sockets

    int listening_fd = create_listener();
    if (listening_fd == -1) {
        fprintf(stderr, "server: error: failed to create listening socket\n");
        return 1;
    }

    int inbound_fd = -1;
    socklen_t sin_size;
    struct sockaddr_storage their_addr;
    while(1) {
        sin_size = sizeof their_addr;
        inbound_fd = accept(listening_fd, (struct sockaddr *)&their_addr, &sin_size);
        if (inbound_fd == -1) {
            perror("server: accept");
            continue;
        }

        printf("server: got connection\n");
        fflush(stdout);

        ssize_t numbytes_recv;
        unsigned char buffer[RECV_BUFFER_SIZE];
        std::vector<unsigned char> pending;
        std::map<int, int> outbound_fds;
        std::map<uint8_t, std::map<uint16_t, std::vector<unsigned char>>> files;
        bool stream_broken = false;

        while ((numbytes_recv = recv(inbound_fd, buffer, sizeof(buffer), 0)) > 0) {
            pending.insert(pending.end(), buffer, buffer + numbytes_recv);

            while (true) {
                if (pending.size() < 4) break;  // Need 4 bytes to tell CTFS from Ethernet

                if (memcmp(pending.data(), MAGIC, 4) == 0) {
                    if (pending.size() < CTFS_HEADER_LEN) break; // Wait for full header 

                    uint16_t seq, len;
                    memcpy(&seq, &pending[4], 2);  seq = ntohs(seq);
                    memcpy(&len, &pending[6], 2);  len = ntohs(len);
                    uint8_t file_id = pending[8];

                    if (len > MAX_PAYLOAD) {
                        stream_broken = true;
                        break;
                    }

                    if (pending.size() < CTFS_HEADER_LEN + len) break; // Wait for full payload

                    if (memcmp(&pending[13], ZERO_PADDING, 3) != 0) {
                        pending.erase(pending.begin(), pending.begin() + CTFS_HEADER_LEN + len);
                        continue; // Invalid padding, skip this packet
                    }

                    if (verify_checksum && !has_valid_checksum(pending.data(), CTFS_HEADER_LEN + len)) {
                        fprintf(stderr, "warning: checksum mismatch (file %u seq %u), packet ignored\n", file_id, seq);
                        pending.erase(pending.begin(), pending.begin() + CTFS_HEADER_LEN + len);
                        continue; // Skip this packet
                    }

                    auto &chunks = files[file_id];
                    if (chunks.count(seq) == 0) {
                        chunks[seq].assign(pending.begin() + CTFS_HEADER_LEN, 
                                            pending.begin() + CTFS_HEADER_LEN + len);
                    } else {
                        fprintf(stderr, "warning: duplicate packet (file %u seq %u) ignored\n", file_id, seq);
                    }
                    pending.erase(pending.begin(), pending.begin() + CTFS_HEADER_LEN + len);
                
                } else {
                    if (pending.size() < ETH_LEN + IP_MIN_LEN) break;  // Wait for the Ethernet + minimum IP header
                
                    struct ether_header eth;
                    struct ip iph;
                    memcpy(&eth, pending.data(), ETH_LEN);
                    memcpy(&iph, pending.data() + ETH_LEN, IP_MIN_LEN);

                    if (ntohs(eth.ether_type) != ETHERTYPE_IP || iph.ip_v != 4) {
                        stream_broken = true;
                        break;
                    }

                    size_t ip_len = ntohs(iph.ip_len);
                    if (ip_len < IP_MIN_LEN) {
                        stream_broken = true;
                        break;
                    }

                    size_t frame_len = ETH_LEN + ip_len;
                    if (pending.size() < frame_len) break;  // Wait for the full frame

                    // Route the frame based on its headers and send it to the appropriate outbound connections
                    for (int port : route_frame(pending.data(), frame_len)) {
                        int outbound_fd = connect_outbound(outbound_fds, port);
                        if (outbound_fd != -1 && !send_all(outbound_fd, pending.data(), frame_len)) {
                            close(outbound_fd);
                            outbound_fds.erase(port);
                        }
                    }
                    pending.erase(pending.begin(), pending.begin() + frame_len);
                }
            }

            if (stream_broken) {
                fprintf(stderr, "error: stream broken, closing connection\n");
                break;
            }
        }
        
        if (!pending.empty()) {
            fprintf(stderr, "warning: %zu bytes of pending data discarded\n", pending.size());
        }

        if (numbytes_recv == -1) {
            perror("server: recv");
        }

        for (auto &[port, fd] : outbound_fds) close(fd);
        if (inbound_fd != -1) close(inbound_fd);

        build_pdf(files);
    }

    return 0;
}
