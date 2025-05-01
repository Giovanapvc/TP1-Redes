import hashlib
import socket
import struct
import sys
import threading
import time
from collections import deque
from typing import Optional

# Sync
SYNC_WORD = 0xDCC023C2 
SYNC_BYTES = struct.pack("!I", SYNC_WORD) * 2   

# Flags
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

# Timeout
RETRANSMIT_TIMEOUT = 1.0  # segundos
MAX_RETRIES = 16

# Checksum
def checksum(data: bytes) -> int:
    """
    Internet Checksum (RFC 1071).
    Soma 16-bit words, faz wrap-around do carry só no final
    e devolve o complemento de 1.
    """
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    # dobra o carry (até não sobrar)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# -------------------- Classe Frame -----------------------------

class Frame:
    __slots__ = ("checksum", "length", "ident", "flags", "payload") # slots pra evitar o Python de fazer dict (otimizar memória)

    def __init__(self, payload: bytes = b"", ident: int = 0, flags: int = 0): # PADRAO: payload vazio, ID=0 e flag indicando que é um ACK
        if len(payload) > MAX_PAYLOAD:
            raise ValueError("Payload must be 4096 bytes maximum.")
        self.payload = payload
        self.length = len(payload)
        self.ident = ident & 0xFFFF # faz um AND binário com 0xFFFF (1111111111111111) o que força o valor do ID caber em 16 bits (ou seja, 2 bytes)
        self.flags = flags & 0xFF # faz um AND binário (11111111) e força a flag a caber em 1 byte
        self.checksum = 0 # checksum só pode ser calculado depois que o frame inteiro for montade

    # ---- serialização ----
    def to_bytes(self) -> bytes: # Converte o objeto Frame em uma sequência de bytes
        header_no_checksum = struct.pack(  # serializa primeiro o header
            "!IIHHHB",
            SYNC_WORD,
            SYNC_WORD,
            0,                # placeholder para o checksum
            self.length,
            self.ident,
            self.flags,
        )
        header_complete = header_no_checksum + self.payload
        self.checksum = checksum(header_complete)
        # monta header final com checksum real
        header = struct.pack(
            "!IIHHHB",
            SYNC_WORD,
            SYNC_WORD,
            self.checksum,
            self.length,
            self.ident,
            self.flags,
        )
        return header + self.payload # retorna o frame serializado em bytes

    # ---- parse ----
    @staticmethod
    def parse_from(buffer: bytearray) -> Optional["Frame"]:  # Optional: Se o frame estiver completo retorna um objeto Frame se não, None
        """Tenta extrair um frame completo do buffer **já alinhado** (dois SYNC no início).
        Retorna Frame se conseguir, None se faltar dados ou checksum falhar (neste caso
        descarta primeiro byte e devolve None).
        """
        if len(buffer) < HEADER_LEN:
            return None  # falta header
        header = buffer[:HEADER_LEN] # pega os primeiros 15 bytes do frame e decodifica nos campos usando unpack
        (
            sync1,
            sync2,
            chksum,
            length,
            ident,
            flags,
        ) = struct.unpack(HEADER_FMT, header)
        if sync1 != SYNC_WORD or sync2 != SYNC_WORD: # verifica a sincronização
            # desalinhado – descarta 1 byte
            buffer.pop(0)
            return None 
        total_len = HEADER_LEN + length 
        if len(buffer) < total_len: # verifica se falta algo
            return None  
        payload = bytes(buffer[HEADER_LEN:total_len]) # extrai apenas o payload
        # valida checksum
        buffer_checksum = bytearray(header) # cria cópia do header
        buffer_checksum[8:10] = b"\x00\x00"  # zera campo checksum
        if checksum(buffer_checksum + payload) != chksum:
            # checksum errado – descarta primeiro byte pra tentar realinhar
            buffer.pop(0)
            return None
        del buffer[:total_len] # remove bytes do buffer
        frame = Frame(payload, ident, flags) # forma o objeto Frame
        frame.checksum = chksum
        return frame

# ------------------- Link DCCNET (stop‑and‑wait) ----------------

class DccnetLink:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.send_id = 0  # próximo ID a transmitir
        self.lock = threading.Lock()             # protege envia/retransmite
        self.ack_event = threading.Event()       # sinaliza ACK para o frame corrente
        self.running = True

        # buffer de recepção e fila para a aplicação
        self._rx_buffer = bytearray()
        self._app_queue = deque()  # bytes prontos para app
        self.peer_no_more_data = False

        # inicia thread de recepção
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    # ------------- API pública ---------------------------------
    def send(self, data: bytes, end: bool = False):
        """Envia dados da aplicação (quebra em blocos <= 4096)."""
        off = 0
        while off < len(data):
            chunk = data[off : off + MAX_PAYLOAD]
            off += len(chunk)
            is_last = off >= len(data) and end
            flags = END_FLAG if is_last else 0
            self._send_data_frame(chunk, flags)
        if end and len(data) == 0:
            # caso queira sinalizar END com frame vazio
            self._send_data_frame(b"", END_FLAG)

    def recv(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Retorna bytes já reassemblados para a aplicação ou None se timeout."""
        t0 = time.time()
        while True:
            if self._app_queue:
                return self._app_queue.popleft()
            if timeout is not None and time.time() - t0 > timeout:
                return None
            time.sleep(0.001)

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    # ------------- envio interno --------------------------------
    def _send_data_frame(self, payload: bytes, flags: int):
        retry = 0
        while retry <= MAX_RETRIES:
            frame = Frame(payload, self.send_id, flags)
            with self.lock:
                self.ack_event.clear()
                frame_bytes = frame.to_bytes()
                print("Enviando frame:", frame_bytes.hex())
                self.sock.sendall(frame_bytes)
            if flags & END_FLAG and len(payload) == 0:
                # frame END vazio – encerra sem esperar ACK
                self.send_id ^= 1        # mantém alternância
                return                   # <-- sai sem cair no timeout
            if self.ack_event.wait(RETRANSMIT_TIMEOUT):
                # ack recebido → alterna ID e sai
                self.send_id ^= 1
                return
            retry += 1
        # se chegou aqui é porque falhou 16 vezes
        rst = Frame(b"Conexao timeout", ident=0xFFFF, flags=RST_FLAG)
        self.sock.sendall(rst.to_bytes())
        self.close()
        raise RuntimeError("Sem ACK apos %d tentativas" % MAX_RETRIES)

    # ------------- recepção -------------------------------------
    def _rx_loop(self):
        last_data_id = None
        last_cksum = None
        while self.running:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self._rx_buffer.extend(chunk)
                while True:
                    # procura alinhamento – dois SYNC consecutivos
                    idx = self._rx_buffer.find(SYNC_BYTES)
                    if idx == -1:
                        # SYNC2 não achado → descarta dados antigos
                        if len(self._rx_buffer) > 8:
                            del self._rx_buffer[:-8]
                        break
                    if idx != 0:
                        del self._rx_buffer[:idx]
                    frame = Frame.parse_from(self._rx_buffer)
                    if not frame:
                        break  # precisa de mais bytes ou checksum falhou
                    # processa frame
                    if frame.flags & ACK_FLAG:
                        # Qualquer ACK libera o transmissor; Stop‑and‑Wait garante 1 frame pendente
                        print("Recebido ACK (id):", frame.ident)
                        self.ack_event.set()
                        continue
                    # data / reset
                    if frame.flags & RST_FLAG:
                        self.close()
                        return
                    # aceita se ID novo ou retransmissão idêntica
                    if frame.ident != last_data_id or frame.checksum == last_cksum:
                        if frame.payload:
                            self._app_queue.append(frame.payload)
                        last_data_id, last_cksum = frame.ident, frame.checksum
                    # manda ACK
                    ack = Frame(b"", ident=frame.ident, flags=ACK_FLAG)
                    self.sock.sendall(ack.to_bytes())
                    if frame.flags & END_FLAG:
                        self.peer_no_more_data = True
            except OSError:
                break
        self.running = False

# ------------------- Aplicação MD5 -----------------------------

def md5_client(addr: str, gas: str):
    host, port_str = addr.rsplit(":", 1)
    port = int(port_str)
    # resolve IPv4/IPv6
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError("Nao foi possivel resolver %s" % host)
    family, socktype, proto, _, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.connect(sockaddr)

    link = DccnetLink(sock)

    # envia GAS
    link.send(gas.encode() + b"\n")

    buffer = b""
    while True:
        data = link.recv(timeout=0.1)
        if data:
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                md5_hex = hashlib.md5(line).hexdigest().encode() + b"\n"
                link.send(md5_hex)
        if link.peer_no_more_data and not buffer:
            # terminou a entrada; manda END vazio para sinalizar que acabou nosso lado
            link.send(b"", end=True)
            break
    link.close()

# ------------------- Main --------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python dccnet_md5.py <IP>:<PORT> <GAS>")
        sys.exit(1)
    md5_client(sys.argv[1], sys.argv[2])
