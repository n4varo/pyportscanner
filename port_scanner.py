import socket
import argparse
import threading
from queue import Queue
import sys
import time
import errno
import ssl
import select

def _grab_banner(sock, port, target, timeout=4.0, attempts=3):
    """
    will patch this function later on for better banner grabbing.
    """
    banner = ""
    try:
        # HTTP probe and ssl wrapping
        if port == 443:
            try:
                ctx = ssl.create_default_context()
                ssl_sock = ctx.wrap_socket(sock, server_hostname=target, do_handshake_on_connect=True)
                try:
                    ssl_sock.settimeout(timeout)
                    # HTTP probe
                    ssl_sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % target.encode())
                    ready = select.select([ssl_sock], [], [], timeout)[0]
                    if ready:
                        banner = ssl_sock.recv(4096).decode("utf-8", errors="ignore").strip()
                finally:
                    try:
                        ssl_sock.close()
                    except Exception:
                        pass
                return banner
            except Exception:
                # fallback: attempt non SSL reads on original socket if wrapping fails
                banner = ""
        # read the data gathered
        for _ in range(attempts):
            ready = select.select([sock], [], [], timeout)[0]
            if ready:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    banner += data.decode("utf-8", errors="ignore")
                    # stop early if we have at least one non-empty line
                    if any(line.strip() for line in banner.splitlines()):
                        break
                except Exception:
                    break
            else:
                # sending probes to the services that usually response if the above fails
                try:
                    if port in (80, 8080, 8000):
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % target.encode())
                    elif port in (21, 23, 25, 110, 143, 993, 995, 22, 5431):
                        
                        sock.sendall(b"\r\n")
                    else:
                        
                        sock.sendall(b"\r\n")
                except Exception:
                
                    pass
               
        if banner:
          
            for line in banner.splitlines():
                if line.strip():
                    return line.strip()
            return banner.strip()
    except Exception:
        return ""
    return ""

print_lock = threading.Lock()
closed_port_count = 0
def scan_port(target, port, args):
    """
    Scans a single port on set target. Gathers banner information if requested.
    """
    global closed_port_count
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((target, port))

        if result == 0:
            with print_lock:
                print(f"[+] Port {port:<5} is open")
            if args.banner:
                # attempt to grab banner without closing socket early
                try:
                    banner = _grab_banner(s, port, target, timeout=1.0, attempts=3)
                    if banner:
                        with print_lock:
                            print(f"    |__Banner: {banner}")
                    else:
                        with print_lock:
                            print(f"    |__Banner: (no banner obtained)")
                except Exception as e:
                    with print_lock:
                        print(f"    |__Banner error: {e}")
        elif result == errno.ECONNREFUSED:
            if args.verbose:
                with print_lock:
                    closed_port_count += 1
                    print(f"[-] Port {port:<5} closed (connection refused)")
        else:
          
            if not getattr(args, "hide_filtered", False):
                with print_lock:
                    print(f"[*] Port {port:<5} is filtered or cannot be reached. (errno: {result})")
    except socket.timeout:
        if not getattr(args, "hide_filtered", False):
            with print_lock:
                print(f"[*] Port {port:<5} is filtered. (timeout)")
    except socket.gaierror:
        with print_lock:
            print(f"[ERR] Could not resolve hostname {target}")
    except Exception as e:
        with print_lock:
            print(f"[ERR] While scanning port {port}. {e}")
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

def worker(q, target, args):
    """
    Worker pulling from the queue
    """
    while not q.empty():
        try:
            port = q.get()
            scan_port(target, port, args)
        finally:
            
            q.task_done()

def main():
    # argparse

    parser = argparse.ArgumentParser(description="Python Port Scanner with threadin")
    
    parser.add_argument('-t', '--target', required=True, help="Hostname or IP address to scan.")
    parser.add_argument('-p', '--ports', default="1-10000", help="Port range to scan (exmp: 80, 22-100, 1-65535(MAX) ). Default: 1-10000")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose mode. Shows closed ports.")
    parser.add_argument('-b', '--banner', action='store_true', help="Try to gather banner information from ports")
    parser.add_argument('-th', '--threads', type=int, default=50, help="Threads to use. Default: 50")
    parser.add_argument('--hide-filtered', action='store_true', help="Hide filtered ports (verbose mode)")
    args = parser.parse_args()

    try:
        # resolving target ip
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] '{args.target}' ({target_ip}) Scanning...")
        print("-" * 50)
    except socket.gaierror:
        print(f"[ERR] Could not resolve target: {args.target}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERR] Unexpected error occurred. {e}")
        sys.exit(1)

    # port range
    port_list = []
    try:
        port_ranges = args.ports.split(',')
        for r in port_ranges:
            if '-' in r:
                start, end = map(int, r.split('-'))
                if start > end: start, end = end, start 
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(r))
        # remove reoccurign ports
        port_list = sorted(list(set(port_list)))
    except ValueError:
        print(f"[ERR] Invalid port range. Please input a range between 1 and 65536")
        sys.exit(1)

    # queue for threading
    q = Queue()
    for port in port_list:
        q.put(port)

    # time
    start_time = time.monotonic()

    # create threads as desired by the user
    thread_count = min(args.threads, len(port_list))
    
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(q, target_ip, args), daemon=True)
        t.start()
        
    # wait for queue
    q.join()

    end_time = time.monotonic()

    print("-" * 50)
    print(f"[*] Scan complete.")
    print(f"[*] Time elapsed: {end_time - start_time:.2f} seconds.")
    if args.verbose:
        print(f"[*] Total closed ports: {closed_port_count}")
if __name__ == "__main__":
    main()
