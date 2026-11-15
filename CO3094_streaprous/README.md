# StreapRous - Stream-based Webapp Routing for Course CO3093/CO3094

Webapp Routing Framework with streaming-based socket HTTP server for HCMC University of Technology Course CO3093/CO3094.

## Run http server backend - must be sudo Linux due to the socket raw capture
```bash
python start_backend 192.168.56.x 9000
```

## Run http server proxy - must be sudo Linux due to the socket raw 

```bash
python start_proxy 192.168.56.x 9000 
```

## Run http webapp StreapRous
```python
#    Entry point for launching the server. This block parses command-line
#    arguments to determine the server's IP address and port.
#    :arg --server-ip (str): IP address to bind the server (default: 127.0.0.1).
#    :arg --server-port (int): Port number to bind the server (default: 9000).
    parser = argparse.ArgumentParser(prog='Proxy', description='', epilog='Proxy daemon')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PROXY_PORT)

    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port

# From start_proxy.py
from daemon import create_proxy

routes = parse_virtual_hosts("config/proxy.conf")
create_proxy(ip, port, routes)

# From start_backend.py
from daemon import create_backend

create_backend(ip, port)

# From start_sampleapp.py
from daemon.streaprous import StreapRous

# Prepare and launch the RESTful application
app.prepare_address(ip, port)
app.run()
```

## Python chat

Each peer registers its ID, username, advertised IP, and port with the tracker,
then polls `POST /api/messages/poll` for queued events.
Broadcast and private messages are delivered from in-memory queues by REST responses.

StreapRous' raw-socket HTTP adapter receives each request with
`run_conn_recv()` and sends its response with `run_conn_send()`; chat event
delivery uses ordinary REST request/response cycles. Use a polling interval
of at least six seconds because the existing raw HTTP adapter holds a
completed connection for five seconds before closing it.

Run a Python chat client in another terminal:

```bash
python client.py --server-host 192.168.56.10 --server-port 2026 --peer-id peer-1 --username Alice --advertised-ip 192.168.56.20
```

The client registers, joins `general`, and polls for events. Type a message to
broadcast it to `general`, or `/quit` to exit. The client does not create a
`StreapRous` server: `StreapRous.run()` starts a listener, whereas this client
connects to the already-running server.

The endpoints are `GET /api/peers`, `POST /api/peers/register`,
`POST /api/peers/unregister`,
`GET /api/channels`, `POST /api/channels/create`, `POST /api/channels/join`,
`GET /api/messages`, `POST /api/messages` (channel broadcast),
`POST /api/messages/direct` (private delivery), and
`POST /api/messages/poll` (queued events). Messages are immutable and limited
to 600 UTF-8 bytes. `client.py` provides Python methods for the REST
endpoints and event polling. The registered peer IP/port are tracker metadata
in this relay design; peers do not connect to those advertised addresses
directly.

## License

See [LICENSE](LICENSE) — educational use only for CO3093/CO3094.