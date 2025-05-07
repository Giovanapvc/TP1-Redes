# dccnet_md5.py – Grading Application 1 + DCCNET
# -----------------------------------------------------------------------------

import hashlib
import socket
import struct
import sys
import threading
import time
from collections import deque
from typing import Optional

SYNC_WORD = 0xDCC023C2 
SYNC_BYTES = struct.pack("!I", SYNC_WORD) * 2   

MAX_PAYLOAD = 4096       # bytes
ACK_FLAG = 0x80          # bit 7
END_FLAG = 0x40          # bit 6
RST_FLAG = 0x20          # bit 5

# Estrutura do header
'''
! = big endian
I = unsigned int (4 bytes)
H = usigned short (2 bytes)
B = unsigned char (1 byte)
Total do header = 15 bytes
'''
HEADER_FMT = "!IIHHHB"   # SYNC, SYNC, chksum, length, id, flags
HEADER_LEN = struct.calcsize(HEADER_FMT)

RETRANSMIT_TIMEOUT = 1.0  # segundos
MAX_RETRIES = 16

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF



class Frame:
    __slots__ = ("_checksum", "_length", "_id", "_flags", "_payload")

    def __init__(self, payload: bytes = b"", id: int = 0, flags: int = 0):
        if len(payload) > MAX_PAYLOAD:
            raise ValueError("Payload must be 4096 bytes maximum.")
        
        self._payload = payload
        self._length = len(payload)
        self._id = id & 0xFFFF 
        self._flags = flags & 0xFF
        self._checksum = 0 

    # Converte objeto Frame em uma sequência de bytes e calcula o checksum
    def toBytes(self) -> bytes: 
        headerNoChecksum = struct.pack(
            "!IIHHHB",
            SYNC_WORD,
            SYNC_WORD,
            0,                # placeholder para o checksum
            self._length,
            self._id,
            self._flags,
        )
        headerComplete = headerNoChecksum + self._payload
        self._checksum = checksum(headerComplete)

        header = struct.pack(
            "!IIHHHB",
            SYNC_WORD,
            SYNC_WORD,
            self._checksum,
            self._length,
            self._id,
            self._flags,
        )
        return header + self._payload

    @staticmethod
    # Tenta extrair 1 frame do buffer alinhado
    def parseFrom(buffer: bytearray) -> Optional["Frame"]:  # Optional: Se o frame estiver completo retorna um objeto Frame se não, None

        if len(buffer) < HEADER_LEN:
            return None
        
        header = buffer[:HEADER_LEN]
        sync1, sync2, chksum, length, id, flags = struct.unpack(HEADER_FMT, header)

        if sync1 != SYNC_WORD or sync2 != SYNC_WORD: 
            buffer.pop(0)
            return None
         
        totalLen = HEADER_LEN + length 
        if len(buffer) < totalLen: 
            return None
          
        payload = bytes(buffer[HEADER_LEN:totalLen]) 

        bufferChecksum = bytearray(header) 
        bufferChecksum[8:10] = b"\x00\x00" 

        if checksum(bufferChecksum + payload) != chksum:
            buffer.pop(0)
            return None
        
        del buffer[:totalLen]

        frame = Frame(payload, id, flags)
        frame._checksum = chksum
        return frame

class DccnetLink:
    def __init__(self, sock: socket.socket): # Construtor instanciado com um socket TCP
        self._sock = sock
        self._sendId = 0 
        self._lock = threading.Lock()             
        self._ackFlag = threading.Event() 
        self._running = True 
        self._lastDataId: Optional[int] = None
        self._lastChecksum:   Optional[int] = None

        self._recepBuffer = bytearray()
        self._readyPayload = deque() 
        self._receivedEndFlag = False

        # Inicia thread de recepção
        self._recepThread = threading.Thread(target=self.recepLoop, daemon=True)
        self._recepThread.start()

    # Envia payloads (dividindo em blocos, sinaliza END se necessário)
    def send(self, data: bytes, end: bool = False):
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + MAX_PAYLOAD]
            offset += len(chunk)
            is_last = offset >= len(data) and end
            flags = END_FLAG if is_last else 0
            self.sendDataFrame(chunk, flags)
        if end and len(data) == 0:
            self.sendDataFrame(b"", END_FLAG)

    # Recebe payload
    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        t0 = time.time()
        while True:
            if self._readyPayload:
                return self._readyPayload.popleft()
            if timeout is not None and time.time() - t0 > timeout:
                return None
            time.sleep(0.001)

    # Fecha o socket e para a thread de recepção
    def close(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
    
    # Envia um frame e gere retransmissões/ACK
    def sendDataFrame(self, payload: bytes, flags: int):
        retry = 0
        while retry <= MAX_RETRIES:
            frame = Frame(payload, self._sendId, flags)
            with self._lock:
                self._ackFlag.clear()
                frame_bytes = frame.toBytes()
                print("Sending frame:", frame_bytes.hex())
                self._sock.sendall(frame_bytes)
            if flags & END_FLAG and len(payload) == 0:
                self._sendId ^= 1        
                return                   
            if self._ackFlag.wait(RETRANSMIT_TIMEOUT):
                self._sendId ^= 1
                return
            retry += 1
        
        rst = Frame(b"Connection timeout", id=0xFFFF, flags=RST_FLAG)
        self._sock.sendall(rst.toBytes())
        self.close()
        raise RuntimeError("No ACK received after %d tries" % MAX_RETRIES)

    # Lê socket, realinha buffer e processa frames
    def recepLoop(self) -> None:
        while self._running:
            try:
                chunk = self._sock.recv(4096)
                if not chunk: 
                    break

                self.feedBuffer(chunk)
                self.resyncBuffer()
                self.processFrames()
            except OSError:
                break

        self.close() 

    # Add bytes recém-chegados ao buffer
    def feedBuffer(self, data: bytes) -> None:
        self._recepBuffer.extend(data)

    # Descarta lixo até encontrar 2 SYNC
    def resyncBuffer(self) -> None:
        idx = self._recepBuffer.find(SYNC_BYTES)
        if idx == -1 and len(self._recepBuffer) > 8:
            del self._recepBuffer[:-8]  
        elif idx > 0:
            del self._recepBuffer[:idx]
    
    # Processa frames completos do buffer
    def processFrames(self) -> None:
        while True:
            frame = Frame.parseFrom(self._recepBuffer)
            if frame is None:
                return 
            
            if frame._flags & ACK_FLAG:
                print(f"ACK({frame._id})")
                self._ackFlag.set()
                continue

            if frame._flags & RST_FLAG:
                self.close()
                return

            isNew = frame._id != self._lastDataId
            isRetransmSame = frame._id == self._lastDataId and frame._checksum == self._lastChecksum

            if isNew:
                if frame._payload:
                    self._readyPayload.append(frame._payload)
                self._lastDataId, self._lastChecksum = frame._id, frame._checksum
            elif isRetransmSame:
                pass

            ack = Frame(b"", id=frame._id, flags=ACK_FLAG)
            self._sock.sendall(ack.toBytes())

            if frame._flags & END_FLAG:
                self._receivedEndFlag = True


# GRAD 1
def md5Client(addr: str, gas: str):
    host, port_str = addr.rsplit(":", 1)
    port = int(port_str)

    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

    if not infos:
        raise RuntimeError("It wasn't possible to resolve %s" % host)
    
    family, socktype, proto, _, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.connect(sockaddr)
    link = DccnetLink(sock)

    link.send(gas.encode() + b"\n")

    buffer = b""

    while True:
        data = link.receive(timeout=0.1)
        if data:
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                md5_hex = hashlib.md5(line).hexdigest().encode() + b"\n"
                link.send(md5_hex)
        if link._receivedEndFlag and not buffer:
            break

    link.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Use: python3 dccnet_md5.py <IP>:<PORT> <GAS>")
        sys.exit(1)
    md5Client(sys.argv[1], sys.argv[2])
