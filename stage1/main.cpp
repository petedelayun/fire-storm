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
#include <algorithm>
#include <map>

const char *const LISTEN_PORT = "5733";
const char *const FORWARD_HOST = "localhost";
const char *const FORWARD_PORT = "5744";
const int BACKLOG = 10;
const size_t RECV_BUFFER_SIZE = 4096;

const unsigned char MAGIC[4] = {'C','T','F','S'};
const size_t CTFS_HEADER_LEN = 16;
const size_t MAX_PAYLOAD = 512;

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

int connect_outbound()
{
    struct addrinfo hints, *results, *ai;
    int outbound_fd = -1;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;          // IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP

    status = getaddrinfo(FORWARD_HOST, FORWARD_PORT, &hints, &results);
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
        fprintf(stderr, "client: error: could not connect to port %s\n", FORWARD_PORT);
        return -1;
    }

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

void build_pdf(std::map<uint16_t, std::vector<unsigned char>> &chunks)
{
    if (!chunks.empty() && (size_t)chunks.rbegin()->first + 1 != chunks.size()) {
        fprintf(stderr, "warning: missing a sequence, the PDF may be incomplete\n");
    }

    FILE *f = fopen("output.pdf", "wb");          // "wb": binary mode
    if (!f) perror("output.pdf");
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

int main(void)
{
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

        int outbound_fd = -1;
        ssize_t numbytes_recv;
        unsigned char buffer[RECV_BUFFER_SIZE];
        std::vector<unsigned char> pending;
        std::map<uint16_t, std::vector<unsigned char>> chunks;

        while ((numbytes_recv = recv(inbound_fd, buffer, sizeof(buffer), 0)) > 0) {
            pending.insert(pending.end(), buffer, buffer + numbytes_recv);

            std::vector<unsigned char> to_forward;
            while (true) {
                auto it = std::search(pending.begin(), pending.end(), MAGIC, MAGIC + 4);

                // (A) No marker anywhere:
                // Send all but the last 3 bytes (in case the marker is split across recv calls)
                if (it == pending.end()) {
                    size_t keep = std::min<size_t>(3, pending.size());
                    size_t n = pending.size() - keep;
                    to_forward.insert(to_forward.end(), pending.begin(), pending.begin() + n);
                    pending.erase(pending.begin(), pending.begin() + n);
                    break;
                }

                // (B) Normal data before the marker:
                // Send all data before the marker, so the marker is at the front of pending
                if (it != pending.begin()) {
                    to_forward.insert(to_forward.end(), pending.begin(), it);
                    pending.erase(pending.begin(), it);
                }

                // (C) Marker at the front, but the header hasn't fully arrived
                if (pending.size() < CTFS_HEADER_LEN) break;

                // (D) Read the header
                uint16_t seq, len;
                memcpy(&seq, &pending[4], 2);  seq = ntohs(seq);
                memcpy(&len, &pending[6], 2);  len = ntohs(len);

                // (E) Length makes no sense: this "CTFS" isn't a real packet
                if (len > MAX_PAYLOAD) {
                    to_forward.insert(to_forward.end(), pending.begin(), pending.begin() + 4);
                    pending.erase(pending.begin(), pending.begin() + 4);
                    continue;                                // Scan for the next marker
                }

                // (F) Header complete, but the payload hasn't fully arrived
                if (pending.size() < CTFS_HEADER_LEN + len) break;

                // (G) Complete packet: copy the payload out, then remove the whole packet
                std::vector<unsigned char> payload(pending.begin() + CTFS_HEADER_LEN, 
                                                    pending.begin() + CTFS_HEADER_LEN + len);
                if (chunks.count(seq) == 0) {
                    chunks[seq] = std::move(payload);
                } else {
                    fprintf(stderr, "warning: duplicate packet (seq %u) ignored\n", seq);
                }
                pending.erase(pending.begin(), pending.begin() + CTFS_HEADER_LEN + len);
            }

            if (outbound_fd == -1) {
                outbound_fd = connect_outbound();
                if (outbound_fd == -1) {
                    fprintf(stderr, "client: error: failed to connect to outbound server\n");
                    break;
                }
            }

            if (!send_all(outbound_fd, to_forward.data(), to_forward.size())) {
                fprintf(stderr, "client: error: failed to send data to outbound server\n");
                break;
            }

        }

        if (outbound_fd == -1) {
            outbound_fd = connect_outbound();
            if (outbound_fd == -1) {
                fprintf(stderr, "client: error: failed to connect to outbound server\n");
            }
        }

        if (outbound_fd != -1 && !send_all(outbound_fd, pending.data(), pending.size())) {
            fprintf(stderr, "client: error: failed to send pending data to outbound server\n");
        }
        
        if (numbytes_recv == -1) {
            perror("server: recv");
        }

        if (outbound_fd != -1) close(outbound_fd);
        if (inbound_fd != -1) close(inbound_fd);

        build_pdf(chunks);
    }

    return 0;
}
