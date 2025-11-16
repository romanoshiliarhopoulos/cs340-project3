#mytrace.py
import argparse
import json
import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_TIME_EXCEEDED = 11
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2


def checksum(string):
    """Calculates checksum (Given by traceroute.py)"""
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count+1]) * 256 + (string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

def jwrite(path, obj):
    """Appends a JSON object to a JSONL file. given"""
    if path is None: return
    obj.setdefault("ts", time.time()) 
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")
        
def build_packet(packet_id, seq):
    """Builds an ICMP Echo Request packet. (Adapted from traceroute.py)"""
    # Header: Type(8), Code(8), Checksum(16), ID(16), Seq(16)
    # Checksum 0 initially
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, packet_id, seq)
    data = struct.pack("d", time.time())
    
    # Calculate checksum and data and header
    pkt_checksum = checksum(header + data)
    
    # Network byte order handling
    if sys.platform == 'darwin':
        pkt_checksum = socket.htons(pkt_checksum) & 0xffff
    else:
        pkt_checksum = socket.htons(pkt_checksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, pkt_checksum, packet_id, seq)
    return header + data

def get_host_info(ip_addr, use_rdns):
    """
    Resolves hostname if --rdns is enabled.
    """
    if not use_rdns:
        return ip_addr
    
    try:
        # Store old timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.2) # 200ms budget
        
        host_entry = socket.gethostbyaddr(ip_addr)
        hostname = host_entry[0]
        
        # Restore timeout
        socket.setdefaulttimeout(old_timeout)
        return f"{hostname} ({ip_addr})"
    except Exception:
        # Restore timeout in case of fail
        socket.setdefaulttimeout(None) 
        return ip_addr

def receive_probe(recv_sock, packet_id, seq, timeout):
    """
    Waits for a response.
    Returns: (router_ip, rtt_ms, type, code, is_target_reached)
    """
    time_left = timeout
    start_select = time.time()
    
    while True:
        what_ready = select.select([recv_sock], [], [], time_left)
        
        if not what_ready[0]: # Timeout
            return None, None, None, False

        try:
            rec_packet, (src_ip, _) = recv_sock.recvfrom(1024)
        except socket.error:
            # Socket error during recv
            return None, None, None, False

        # Parse IP Header
        ip_header = rec_packet[0:20]
        ip_header_len = (ip_header[0] & 0x0F) * 4
        
        # Parse ICMP Header
        icmp_packet = rec_packet[ip_header_len:]
        # Ensure we have enough bytes for ICMP header (8)
        if len(icmp_packet) < 8:
            continue

        icmp_header = icmp_packet[0:8]
        icmp_type, icmp_code, _, rcv_id, rcv_seq = struct.unpack("bbHHh", icmp_header)
        
        # Echo Reply (Type 0) -we have reached the destination
        if icmp_type == ICMP_ECHO_REPLY:
            if rcv_id == packet_id and rcv_seq == seq:
                # Calculate RTT outside of this function, in traceroute()
                data_payload = icmp_packet[8:]
                if len(data_payload) >= 8: 
                    return src_ip, icmp_type, icmp_code, True

        # Time Exceeded (Type 11) Intermediate Router
        elif icmp_type == ICMP_TIME_EXCEEDED:
            # Payload contains original IP Header + first 8 bytes of original ICMP
            inner_ip_off = ip_header_len + 8
            inner_ip_header = rec_packet[inner_ip_off : inner_ip_off + 20]
            inner_ip_len = (inner_ip_header[0] & 0x0F) * 4
            
            inner_icmp_off = inner_ip_off + inner_ip_len
            inner_icmp_header = rec_packet[inner_icmp_off : inner_icmp_off + 8]
            
            _, _, _, orig_id, orig_seq = struct.unpack("bbHHh", inner_icmp_header)
            
            if orig_id == packet_id and orig_seq == seq:
                return src_ip, icmp_type, icmp_code, False

        # Recalculate timeout
        time_left = timeout - (time.time() - start_select)
        if time_left <= 0:
            return None, None, None, False
        
        
def traceroute(target, 
               max_ttl, 
               num_probes, 
               timeout, 
               resolve_hostnames, 
               rdns, 
               flow_id, 
               json_output, 
               qps_limit, 
               no_color,
               i_accept_the_risk):
    
    #ethics and safety check
    min_interval = 1.0 / qps_limit
    if min_interval < 1.0 and not i_accept_the_risk:
        print("Error: QPS Limit. Use --i-accept-the-risk to override.", file=sys.stderr)
        sys.exit(1)

    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"Error: Cannot resolve {target}: {e}")
        return

    print(f"traceroute to {target} ({dest_ip}), {max_ttl} hops max, {num_probes} probes/hop")

    # Create Socket
    try:
        icmp_proto = socket.getprotobyname("icmp")
        snd_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
    except Exception as e:
        print("Exception: ", e)
        sys.exit(1)

    # Use flow_id as the ICMP Identifier if provided, otherwise PID
    packet_id = (flow_id if flow_id > 0 else os.getpid()) & 0xFFFF

    seq_counter = 0
    destination_reached = False

    for ttl in range(1, max_ttl + 1):
        # Print Hop Number
        print(f"{ttl:2d}  ", end="", flush=True)
        
        # Set TTL on socket
        snd_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        
        # Track previous router IP to format output
        prev_router_ip = None
        
        stats_rtts = []

        #for each probe
        for probe in range(num_probes):
            seq_counter += 1
            
            # Enforce Rate Limit
            if qps_limit > 0:
                time.sleep(1.0 / qps_limit)

            packet = build_packet(packet_id, seq_counter)
            
            ts_send = time.time()
            #send
            snd_sock.sendto(packet, (dest_ip, 1))
            #receive
            router_ip, icmp_type, icmp_code, is_target = receive_probe(snd_sock, packet_id, seq_counter, timeout)
            ts_recv = time.time()
            
            # Calculate RTT
            if router_ip:
                rtt_ms = (ts_recv - ts_send) * 1000
                stats_rtts.append(rtt_ms)
            else:
                rtt_ms = None

            # JSON Logging 
            log_entry = {
                "tool": "trace",
                "hop": ttl,
                "probe": probe + 1,
                "ts_send": ts_send,
                "ts_recv": ts_recv if router_ip else None,
                "dst": target,
                "router_ip": router_ip,
                "rtt_ms": rtt_ms,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "flow_id": packet_id,
                "err": None if router_ip else "timeout"
            }
            jwrite(json_output, log_entry)

            # Console Output
            if router_ip:
                if router_ip != prev_router_ip:
                    if rdns:
                        host_str = get_host_info(router_ip, True)
                        print(f"{host_str}  ", end="", flush=True)
                    else:
                        print(f"{router_ip}  ", end="", flush=True)
                    prev_router_ip = router_ip
                
                print(f"{rtt_ms:.3f} ms  ", end="", flush=True)
                
                if is_target:
                    destination_reached = True
            else:
                print("* ", end="", flush=True)
        
        # End of Hop Line
        print("") 
        
        if destination_reached:
            break

    snd_sock.close()


def main():
    parser = argparse.ArgumentParser(description="ICMP Traceroute")
    parser.add_argument("target", help="Hostname or IP to trace")
    parser.add_argument("--max-ttl", type=int, default=30, help="Maximum TTL (hops)")
    parser.add_argument("--probes", type=int, default=3, help="Probes per hop")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout (s)")
    parser.add_argument("-n", action="store_true", help="Do not resolve hostnames (show IP only)")
    parser.add_argument("--rdns", action="store_true", help="Enable reverse DNS (200 ms budget per hop)")
    parser.add_argument("--flow-id", type=int, default=0,
                        help="Flow ID to keep probes consistent (Paris-style)")
    parser.add_argument("--json", type=str, help="Write per-probe results to JSONL file")
    parser.add_argument("--qps-limit", type=float, default=1.0,
                        help="Max probe rate (queries per second)")
    parser.add_argument("--no-color", action="store_true", help="Disable color in output")
    parser.add_argument("--i-accept-the-risk", action="store_true", help="Accept high QPS risk")

    args = parser.parse_args()
    
    # Logic to handle conflicting DNS flags
    # prioritize -n.
    use_rdns = args.rdns and not args.n

    traceroute(target=args.target, 
               max_ttl=args.max_ttl, 
               num_probes=args.probes, 
               timeout=args.timeout, 
               resolve_hostnames=not args.n, 
               rdns=use_rdns, 
               flow_id=args.flow_id, 
               json_output=args.json, 
               qps_limit=args.qps_limit, 
               no_color=args.no_color,
               i_accept_the_risk=args.i_accept_the_risk)

if __name__ == "__main__":
    main()
