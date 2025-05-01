# dccnet_xfer.py – Grading Application 2 (transferência de arquivos bidirecional)
# -----------------------------------------------------------------------------
# Server (passivo):
#   python dccnet_xfer.py -s <PORT> <INPUT> <OUTPUT>
# Cliente (ativo):
#   python dccnet_xfer.py -c <IP>:<PORT> <INPUT> <OUTPUT>
# -----------------------------------------------------------------------------
# Requisitos atendidos:
# • Usa a mesma implementação de DCCNET (classe DccnetLink) já testada no MD5.
# • Envia o arquivo <INPUT> para o outro lado, fragmentando em frames de até 4096 B.
# • Simultaneamente grava tudo que chegar do outro lado em <OUTPUT>.
# • Quando ambos os lados terminam de enviar (flag END) e receber, fecha a conexão.
# -----------------------------------------------------------------------------

import argparse
import os
import socket
import threading
from pathlib import Path

from dccnet_md5 import DccnetLink  # reaproveitamos a classe já validada

CHUNK = 4096  # mesmo limite do payload DCCNET

def send_file(link: DccnetLink, infile: Path):
    """Lê <infile> e envia via link, terminando com frame END."""
    with infile.open("rb") as f:
        while True:
            data = f.read(CHUNK)
            if not data:
                break
            link.send(data)
    # sinaliza fim do envio
    link.send(b"", end=True)

def recv_file(link: DccnetLink, outfile: Path):
    """Recebe bytes do link e grava em <outfile> até peer mandar END."""
    with outfile.open("wb") as f:
        while True:
            data = link.recv(timeout=0.1)
            if data:
                f.write(data)
            if link.peer_no_more_data:
                break

def run_client(addr: str, infile: Path, outfile: Path):
    host, port_str = addr.rsplit(":", 1)
    port = int(port_str)
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.connect(sockaddr)
    link = DccnetLink(sock)
    _run_transfer(link, infile, outfile)

def run_server(port: int, infile: Path, outfile: Path):
    # IPv6 server que escuta em todas as interfaces (IPv4-mapped também funciona)
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("::", port))
    srv.listen(1)
    print(f"[dccnet-xfer] Aguardando conexão em :{port} ...")
    conn, addr = srv.accept()
    print(f"[dccnet-xfer] Conexão de {addr}")
    link = DccnetLink(conn)
    _run_transfer(link, infile, outfile)

def _run_transfer(link: DccnetLink, infile: Path, outfile: Path):
    tx_done = threading.Event()
    rx_done = threading.Event()

    def tx():
        send_file(link, infile)
        tx_done.set()

    def rx():
        recv_file(link, outfile)
        rx_done.set()

    threading.Thread(target=tx, daemon=True).start()
    threading.Thread(target=rx, daemon=True).start()

    # espera ambos terminarem
    tx_done.wait()
    rx_done.wait()
    link.close()
    print("[dccnet-xfer] Transferência concluída. Saindo…")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DCCNET bidirectional file transfer")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-s", metavar="PORT", type=int, help="Servidor passivo – porta para escutar")
    mode.add_argument("-c", metavar="IP:PORT", help="Cliente ativo – endereço e porta do servidor")
    parser.add_argument("INPUT", type=Path, help="Arquivo a enviar")
    parser.add_argument("OUTPUT", type=Path, help="Arquivo onde salvará o que receber")
    args = parser.parse_args()

    if args.s is not None:
        run_server(args.s, args.INPUT, args.OUTPUT)
    else:
        run_client(args.c, args.INPUT, args.OUTPUT)
