# **WebSocket Protocol (RFC 6455\) \- Cheat Sheet**

## **1\. The Handshake (The "Upgrade")**

Before binary data can flow, the connection must upgrade from HTTP to WebSocket.

**Client Request:**

GET /chat HTTP/1.1  
Host: server.example.com  
Upgrade: websocket  
Connection: Upgrade  
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==  \<-- Random Base64  
Sec-WebSocket-Version: 13

**Server Response (The Algorithm):**

1. Take Sec-WebSocket-Key.  
2. Append Magic String: 258EAFA5-E914-47DA-95CA-C5AB0DC85B11  
3. Compute SHA-1 Hash.  
4. Encode result in Base64.

HTTP/1.1 101 Switching Protocols  
Upgrade: websocket  
Connection: Upgrade  
Sec-WebSocket-Accept: s3pPLMBiTxgJFtMuwJTMnKRxkxE=

## **2\. The Frame Anatomy**

Every message is wrapped in a binary frame.

**Byte 0: Meta Data**

  7 6 5 4 3 2 1 0  (Bits)  
 \+-+-+-+-+-------+  
 |F|R|R|R| Opcode|  
 |I|S|S|S|  (4)  |  
 |N|V|V|V|       |  
 \+-+-+-+-+-------+

* **FIN (Bit 7):** 1 \= End of message. 0 \= More fragments coming.  
* **RSV1-3:** Reserved (usually 0).  
* **Opcode (Bits 0-3):** Defines payload type.  
  * 0x1 \= Text  
  * 0x2 \= Binary  
  * 0x8 \= Close  
  * 0x9 \= Ping (Heartbeat)  
  * 0xA \= Pong (Heartbeat Reply)

**Byte 1: Mask & Length**

  7 6 5 4 3 2 1 0  
 \+-+-+-----------+  
 |M| Payload Len |  
 |A|     (7)     |  
 |S|             |  
 |K|             |  
 \+-+-+-----------+

* **MASK (Bit 7):** 1 if masked (Client \-\> Server). 0 if raw (Server \-\> Client).  
* **Payload Len (Bits 0-6):**  
  * 0-125: Actual length.  
  * 126: Read next **2 bytes** (16-bit integer) for length.  
  * 127: Read next **8 bytes** (64-bit integer) for length.

## **3\. The Data Flow Logic**

### **A. Reading a Message**

1. **Read Byte 0:**  
   * Opcode \= byte\[0\] & 15  
   * If Opcode \== 8, Close Connection.  
   * If Opcode \== 9, Prepare Pong.  
2. **Read Byte 1:**  
   * Length \= byte\[1\] & 127  
3. **Check Extended Length:**  
   * If Length \== 126, Read 2 bytes (big-endian).  
   * If Length \== 127, Read 8 bytes.  
4. **Read Masking Key:**  
   * If MASK bit was 1, Read next 4 bytes.  
5. **Decode (Unmask):**  
   * Loop i from 0 to Length:  
   * DecodedByte \= Buffer\[DataStart \+ i\] ^ MaskKey\[i % 4\]

### **B. Sending a Message**

* **No Masking:** Server does not mask data sent to client.  
* **Construct Byte 0:** 129 (Text) or 130 (Binary).  
  * *Formula:* (FIN \<\< 7\) | Opcode \=\> 128 | 1 \= 129\.  
* **Construct Byte 1:** Length (0-125).  
  * *Formula:* 0 | Length (Mask bit is 0).

## **4\. Control Frame Reference**

| Frame Type | Opcode (Hex) | Byte 0 Value (FIN=1) | Payload Rules |
| :---- | :---- | :---- | :---- |
| **Text** | 0x1 | 129 (0x81) | UTF-8 text data. |
| **Binary** | 0x2 | 130 (0x82) | Raw binary data. |
| **Close** | 0x8 | 136 (0x88) | Can contain status code (2 bytes). |
| **Ping** | 0x9 | 137 (0x89) | Keep-alive. Max len 125\. |
| **Pong** | 0xA | 138 (0x8A) | Must echo Ping payload. |
