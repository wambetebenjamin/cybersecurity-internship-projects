import socket
import threading
import logging
from queue import Queue

TIMEOUT = 1
MAX_THREADS = 100
LOG_FILE = "scan_results.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

print_lock = threading.Lock()
queue = Queue()

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        result = sock.connect_ex((host, port))
        with print_lock:
            if result == 0:
                print(f"[OPEN] Port {port}")
                logging.info(f"Port {port} OPEN")
            else:
                print(f"[CLOSED] Port {port}")
                logging.info(f"Port {port} CLOSED")
    except socket.timeout:
        with print_lock:
            print(f"[TIMEOUT] Port {port}")
            logging.info(f"Port {port} TIMEOUT")
    except Exception as e:
        with print_lock:
            print(f"[ERROR] Port {port}: {e}")
            logging.error(f"Port {port} ERROR: {e}")
    finally:
        sock.close()

def worker(host):
    while not queue.empty():
        port = queue.get()
        scan_port(host, port)
        queue.task_done()

def start_scan(host, start_port, end_port):
    print(f"\nScanning host: {host}")
    print(f"Ports: {start_port} - {end_port}\n")

    for port in range(start_port, end_port + 1):
        queue.put(port)

    for _ in range(min(MAX_THREADS, queue.qsize())):
        thread = threading.Thread(target=worker, args=(host,))
        thread.daemon = True
        thread.start()

    queue.join()
    print("\nScan completed.")
    print(f"Results saved in {LOG_FILE}")

if __name__ == "__main__":
    host = input("Enter target host (IP or domain): ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    start_scan(host, start_port, end_port)
