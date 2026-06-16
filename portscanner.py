import argparse
import socket
import ipaddress
import time
import threading
from queue import Queue, PriorityQueue

# --- Argument Definition ---
parser = argparse.ArgumentParser(prog='port-scanner', description='Multithreaded Port Scanner')

parser.add_argument('-sh', '--starthost', action='store', required=True, help='Start IP address')
parser.add_argument('-eh', '--endhost', action='store', required=True, help='End IP address')
parser.add_argument('-sp', '--startport', action='store', type=int, help='Start port')
parser.add_argument('-ep', '--endport', action='store', type=int, help='End port')
parser.add_argument('-wk', '--wellknown', action='store_true', default=False, help='Scan only well-known ports (0-1023)')
parser.add_argument('-th', '--threads', action='store', type=int, default=10, help='Number of worker threads (default: 10)')

args = parser.parse_args()

# --- Argument Validierung ---
# Entweder -wk oder -sp/-ep muss angegeben werden
if not args.wellknown:
    if args.startport is None or args.endport is None:
        parser.error("Ohne -wk musst du -sp und -ep angeben.")
    start_port = args.startport
    end_port = args.endport
else:
    start_port = 0
    end_port = 1023

try:
    start_host = int(ipaddress.IPv4Address(args.starthost))
except ValueError:
    parser.error("Ungültige Start - IP")
try:
    end_host = int(ipaddress.IPv4Address(args.endhost))
except ValueError:
    parser.error("Ungültige End - IP")
threads = args.threads

print(f"Scan von {args.starthost} bis {args.endhost}, Ports {start_port}-{end_port}, {threads} Threads")

# --- Shared State ---
open_ports = []
print_lock = threading.Lock()


# --- Scan Logik ---
def single_scan(ip, port):
    """Versucht eine TCP-Verbindung auf ip:port, speichert offene Ports."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        is_open = s.connect_ex((ip, port))
        if is_open == 0:
            with print_lock:
                print(f"  [OPEN] {ip}:{port}")
                open_ports.append((ip, port))

def print_every_second():
    while True:
        if int(time.perf_counter() - start_time) % 10 == 0 and int(time.perf_counter() - start_time) != 0:
            print(f"Time past: {int(time.perf_counter() - start_time)}")
        time.sleep(1)

# --- Worker Thread ---
def threader():
    """Holt Jobs aus der Queue und scannt sie, bis das Programm endet."""
    while True:
        ip_str, port = q.get()
        single_scan(ip_str, port)
        q.task_done()


# --- Threading Setup ---
q = Queue()
start_time = time.perf_counter()
time_thread = threading.Thread(target=print_every_second, daemon=True)
time_thread.start()

for _ in range(threads):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

# --- Queue befüllen ---


for ip in range(start_host, end_host + 1):
    ip_str = str(ipaddress.IPv4Address(ip))
    for port in range(start_port, end_port + 1):
        q.put((ip_str, port))

q.join()

# --- Ergebnis ---
ende = time.perf_counter()
print(f"\nScan abgeschlossen in {ende - start_time:.2f} Sekunden")
print(f"Offene Ports ({len(open_ports)}):")
for ip, port in sorted(open_ports):
    print(f"  {ip}:{port}")