# dccnet_xfer.py – Grading Application 2 
# -----------------------------------------------------------------------------
# Server:
#   python dccnet_xfer.py -s <PORT> <INPUT> <OUTPUT>
# Client:
#   python dccnet_xfer.py -c <IP>:<PORT> <INPUT> <OUTPUT>
# -----------------------------------------------------------------------------

USAGE = """
Uso:
  # Server mode (passive):
  python dccnet_xfer.py -s <PORTA> <INPUT> <OUTPUT>

  # Client mode (active):
  python dccnet_xfer.py -c <IP:PORTA> <INPUT> <OUTPUT>
"""

import sys
import socket
import threading
from pathlib import Path

from dccnet_md5 import DccnetLink 

CHUNK = 4096 

# Envia arquivo via link e fecha com END
def sendFile(link: DccnetLink, infile: Path):
    with infile.open("rb") as f:
        while True:
            data = f.read(CHUNK)
            if not data:
                break
            link.send(data)

    link.send(b"", end=True)

# Grava tudo que chegar no link até END
def receiveFile(link: DccnetLink, outfile: Path):
    with outfile.open("wb") as f:
        while True:
            data = link.receive(timeout=0.1)
            if data:
                f.write(data)
            if link._receivedEndFlag:
                break

# Starta Client: abre TCP e começa a transferência
def runClient(addr: str, infile: Path, outfile: Path):
    host, port_str = addr.rsplit(":", 1)
    port = int(port_str)
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.connect(sockaddr)
    link = DccnetLink(sock)
    runTransfer(link, infile, outfile)

# Starta Server: aceita 1 conexão e começa a transferência
def runServer(port: int, infile: Path, outfile: Path):
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("::", port))
    srv.listen(1)
    print(f"[dccnet-xfer - SERVER] Waiting for connection in :{port} ...")
    conn, addr = srv.accept()
    print(f"[dccnet-xfer - SERVER] Connection established with {addr}")
    link = DccnetLink(conn)
    runTransfer(link, infile, outfile)

# Roda threads de envio e recepção, espera ambas, fecha link
def runTransfer(link: DccnetLink, infile: Path, outfile: Path) -> None:
    sendDone = threading.Event()
    receiveDone = threading.Event()

    def transmition():
        sendFile(link, infile)
        sendDone.set()

    def reception():
        receiveFile(link, outfile)
        receiveDone.set()

    threading.Thread(target=transmition, daemon=True).start()
    threading.Thread(target=reception, daemon=True).start()

    sendDone.wait()
    receiveDone.wait()
    link.close()
    print("[dccnet-xfer] Transfer completed. Ending…")

# Parser da linha de comando
def parseArgs(argv):
    if len(argv) != 5:
        sys.exit(USAGE)

    mode, endpoint, in_file, out_file = argv[1:]
    if mode == "-s":
        port = int(endpoint)
        return ("server", port, Path(in_file), Path(out_file))
    elif mode == "-c":
        return ("client", endpoint, Path(in_file), Path(out_file))
    else:
        sys.exit(USAGE)

if __name__ == "__main__":
    role, addr, in_path, out_path = parseArgs(sys.argv)

    if role == "server":
        runServer(addr, in_path, out_path)
    else:
        runClient(addr, in_path, out_path)
