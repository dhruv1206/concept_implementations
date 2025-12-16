#include <cstdint>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#endif
#include <io.h>
#include <vector>
using namespace std;

string get_websocket_key(const char *buffer)
{
    const char *key_header = "Sec-WebSocket-Key:";
    const char *target = strstr(buffer, key_header);

    if (target)
    {
        // Move past the "Sec-WebSocket-Key:" part
        target += strlen(key_header);

        // Skip any spaces immediately following the colon
        while (*target == ' ')
        {
            target++;
        }

        // Find the end of the line (CRLF which is \r\n)
        const char *end = strstr(target, "\r\n");
        if (end)
        {
            // Return the substring between start and end
            return std::string(target, end - target);
        }
    }
    return "";
}

// Rotates x left n bits
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

std::string sha1(const std::string &input)
{
    // 1. Prepare variables
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

    // 2. Pre-processing: Padding
    std::string msg = input;
    uint64_t initial_len = msg.length() * 8; // Length in bits
    msg += (char)0x80;                       // Append single '1' bit (0x80 = 10000000)

    // Append 0s until length % 512 == 448
    while ((msg.length() * 8) % 512 != 448)
    {
        msg += (char)0x00;
    }

    // Append original length as 64-bit integer (Big Endian)
    for (int i = 7; i >= 0; --i)
    {
        msg += (char)((initial_len >> (i * 8)) & 0xFF);
    }

    // 3. Process the message in 512-bit (64-byte) chunks
    for (size_t i = 0; i < msg.length(); i += 64)
    {
        uint32_t w[80];
        // Break chunk into sixteen 32-bit big-endian words
        for (int j = 0; j < 16; ++j)
        {
            w[j] = ((unsigned char)msg[i + j * 4] << 24) | ((unsigned char)msg[i + j * 4 + 1] << 16) |
                   ((unsigned char)msg[i + j * 4 + 2] << 8) | ((unsigned char)msg[i + j * 4 + 3]);
        }
        // Extend the sixteen 32-bit words into eighty 32-bit words
        for (int j = 16; j < 80; ++j)
        {
            w[j] = ROL(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int j = 0; j < 80; ++j)
        {
            uint32_t f, k;
            if (j < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (j < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = ROL(a, 5) + f + e + k + w[j];
            e = d;
            d = c;
            c = ROL(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // 4. Produce the final hash (20 bytes)
    char finalHash[20];
    auto store = [&](uint32_t v, int offset)
    {
        finalHash[offset] = (v >> 24) & 0xFF;
        finalHash[offset + 1] = (v >> 16) & 0xFF;
        finalHash[offset + 2] = (v >> 8) & 0xFF;
        finalHash[offset + 3] = v & 0xFF;
    };

    store(h0, 0);
    store(h1, 4);
    store(h2, 8);
    store(h3, 12);
    store(h4, 16);

    return std::string(finalHash, 20);
}
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::string &in)
{
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

const string websocket_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

int main()
{
    // Windows Specific handling
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    // Domain: AF_INET (IPv4)
    // Type: SOCK_STREAM (TCP, reliable, connection-based)
    // Protocol: 0 (Let OS choose the default for the type, usually TCP)
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0)
    {
        cout << "Socket creation failed!!" << endl;
        return -1;
    }
    cout << "Socket created successfully" << endl;

    // Define the address structure
    struct sockaddr_in address;
    const int PORT = 8080;

    address.sin_family = AF_INET;         // IPv4
    address.sin_addr.s_addr = INADDR_ANY; // Bind to any IP
    address.sin_port = htons(PORT);       // Host to Network Short

    // Step 2: Bind the socket to the address/port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        return 1;
    }

    // Step 3: Start listening (queue up to 3 pending connections)
    if (listen(server_fd, 3) < 0)
    {
        perror("Listen failed");
        return 1;
    }

    std::cout << "Server is listening on port " << PORT << "..." << std::endl;

    int addrlen = sizeof(address);
    // This blocks (waits) until a client connects
    int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);

    char buffer[1024] = {0};
    // in Linux/Unix read(socket_fd, buffer, buffer_size)
    recv(new_socket, buffer, 1024, 0);
    std::cout << "Received Request:\n"
              << buffer << std::endl;

    string websocket_key = get_websocket_key(buffer);
    cout << "Websocket key: " << websocket_key << endl;
    string contatenated_key = websocket_key + websocket_magic_string;
    string hashed_key = sha1(contatenated_key);
    string accept_key = base64_encode(hashed_key);
    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: " +
                           accept_key + "\r\n\r\n";
    send(new_socket, response.c_str(), response.size(), 0);
    std::cout << "Handshake sent!" << std::endl;
    memset(buffer, 0, 1024);
    int valread = recv(new_socket, buffer, 1024, 0);
    if (valread > 0)
    {
        cout << "Recieved first message after websocket upgrade: " << buffer << endl;
        unsigned char byte0 = buffer[0];
        unsigned char byte1 = buffer[1];

        std::cout << "Byte 0: " << (int)byte0 << std::endl;
        std::cout << "Byte 1: " << (int)byte1 << std::endl;

        // Unmask the single byte
        char decoded = buffer[6] ^ buffer[2];
        std::cout << "Decoded message: " << decoded << std::endl;

        char reply[3] = {char(129), char(1), 'A'};
        send(new_socket, reply, 3, 0);
    }
    int payload_length = buffer[1] & 127;

    // 2. Prepare the masking key location
    // Key starts at buffer[2]

    std::cout << "Decoded message: ";
    while (true)
    {
        std::vector<uint8_t> buf(4096);
        int valread = recv(new_socket, reinterpret_cast<char *>(buf.data()), (int)buf.size(), 0);
        if (valread <= 0)
            break;

        size_t bytes_available = (size_t)valread;
        if (bytes_available < 2)
            continue; // need at least 2 bytes for header

        uint8_t byte0 = buf[0];
        uint8_t byte1 = buf[1];

        int opcode = byte0 & 0x0F;
        if (opcode == 0x8) // CLOSE
        {
            std::cout << "CLOSE Frame Received\n";
            break;
        }

        bool masked = (byte1 & 0x80) != 0;
        uint64_t payload_len = byte1 & 0x7F;
        size_t header_len = 2;

        if (payload_len == 126)
        {
            if (bytes_available < header_len + 2)
                continue;
            payload_len = (uint64_t)((buf[2] << 8) | buf[3]);
            header_len += 2; // now header is 4 bytes before mask
        }
        else if (payload_len == 127)
        {
            if (bytes_available < header_len + 8)
                continue;
            payload_len = 0;
            for (int i = 0; i < 8; ++i)
            {
                payload_len = (payload_len << 8) | buf[2 + i];
            }
            header_len += 8; // now header is 10 bytes before mask
        }

        uint8_t mask_key[4] = {0, 0, 0, 0};
        if (masked)
        {
            // mask key is immediately after the length bytes
            if (bytes_available < header_len + 4)
                continue;
            size_t mask_offset = header_len;
            mask_key[0] = buf[mask_offset + 0];
            mask_key[1] = buf[mask_offset + 1];
            mask_key[2] = buf[mask_offset + 2];
            mask_key[3] = buf[mask_offset + 3];
            header_len += 4; // data starts after mask
        }

        // Ensure we have the full payload in the buffer (simple check for single recv)
        if (bytes_available < header_len + payload_len)
        {
            // In production you should read repeatedly until you have the full frame.
            // For now just continue (or handle partial frames).
            continue;
        }

        // Unmask payload into a contiguous vector
        std::vector<uint8_t> payload;
        payload.resize((size_t)payload_len);
        for (size_t i = 0; i < payload_len; ++i)
        {
            uint8_t b = buf[header_len + i];
            if (masked)
                b ^= mask_key[i % 4];
            payload[i] = b;
        }

        // Debug print (safe): print as string if it's text (opcode == 1)
        if (opcode == 1)
        {
            std::string s(payload.begin(), payload.end());
            std::cout << "Received text payload: " << s << std::endl;
        }
        else
        {
            std::cout << "Received binary/other payload, length=" << payload_len << std::endl;
        }

        // Build server response (unmasked). We'll set FIN=1 and opcode same as client (or 0x1 for text).
        // For simplicity we echo back as a text frame FIN=1, opcode=1 if original was text.
        uint8_t resp_opcode = (opcode == 1) ? 0x1 : (opcode == 9) ? 10
                                                                  : opcode;
        uint8_t resp_first = 0x80 | (resp_opcode & 0x0F); // FIN + opcode

        // Determine header length for server frame
        std::vector<uint8_t> resp;
        if (payload_len <= 125)
        {
            resp.resize(2 + payload_len);
            resp[0] = resp_first;
            resp[1] = static_cast<uint8_t>(payload_len); // mask bit 0
            std::copy(payload.begin(), payload.end(), resp.begin() + 2);
        }
        else if (payload_len <= 0xFFFF)
        {
            resp.resize(4 + payload_len);
            resp[0] = resp_first;
            resp[1] = 126;                                             // indicates 16-bit length follows
            resp[2] = static_cast<uint8_t>((payload_len >> 8) & 0xFF); // big-endian
            resp[3] = static_cast<uint8_t>(payload_len & 0xFF);
            std::copy(payload.begin(), payload.end(), resp.begin() + 4);
        }
        else
        {
            resp.resize(10 + payload_len);
            resp[0] = resp_first;
            resp[1] = 127; // indicates 64-bit length follows
            // write 64-bit big-endian length
            uint64_t L = payload_len;
            for (int i = 0; i < 8; ++i)
            {
                resp[9 - i] = static_cast<uint8_t>(L & 0xFF);
                L >>= 8;
            }
            resp[1] = 127;
            // copy payload after 10-byte header
            std::copy(payload.begin(), payload.end(), resp.begin() + 10);
        }

        // Send the response
        ssize_t sent = send(new_socket, reinterpret_cast<const char *>(resp.data()), (int)resp.size(), 0);
        if (sent < 0)
        {
            perror("send");
            break;
        }

        // Optionally break on a "Bye" message
        if (payload_len == 3 && payload[0] == 'B' && payload[1] == 'y' && payload[2] == 'e')
        {
            break;
        }
    }
    std::cout << std::endl;

    return 0;
}