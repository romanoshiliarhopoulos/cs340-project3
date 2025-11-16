import argparse
import json
import socket
import os
import sys
import struct
import time
import select
import binascii


#ICMP TYPES
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_TIME_EXCEEDED = 11

ICMP_TYPE_STR = {
    3: {
        0: "Net Unreachable",
        1: "Host Unreachable",
        3: "Port Unreachable",
    },
    11: {
        0: "TTL Expired in Transit",
    }
}

def get_icmp_error_str(icmp_type: int, icmp_code: int) -> str:
    """Returns a string for an ICMP type/code."""
    if icmp_type in ICMP_TYPE_STR and icmp_code in ICMP_TYPE_STR[icmp_type]:
        return ICMP_TYPE_STR[icmp_type][icmp_code]
    return f"Type={icmp_type}, Code={icmp_code}"

# provided stats class using Welford's algorithm
class OnlineStats:
    def __init__(self):
        self.n = 0; self.mean = 0.0; self.M2 = 0.0
        self.min = float('inf'); self.max = float('-inf')
    def add(self, x):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.M2 += d * (x - self.mean)
        self.min = min(self.min, x); self.max = max(self.max, x)
    def summary(self):
        var = self.M2 / (self.n - 1) if self.n > 1 else 0.0
        return {"count": self.n, "min": self.min, "avg": self.mean,
                "max": self.max, "stddev": var ** 0.5}

def jwrite(path, obj):
    """Appends a JSON object to a JSONL file. given"""
    if path is None: return
    obj.setdefault("ts", time.time()) 
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")

def checksum(string):
    """Calculates checksum (given ping.py)"""
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
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

def send_one_ping(mySocket, destAddr, ID, seq):
    """Sends single ping, corrected to use seq. Changed from initial"""
    myChecksum = 0
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # Pack the seq argument
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq)
    data = struct.pack("d", time.time())
    
    # Calculate checksum on bytes decoded
    packet_bytes = header + data
    myChecksum = checksum(packet_bytes.decode('latin-1'))

    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq)
    packet = header + data
    
    ts_send = time.time()
    mySocket.sendto(packet, (destAddr, 1))
    return ts_send

def receive_one_ping(mySocket, ID, timeout, destAddr, seq) ->dict:
    """Listener for receving pings. Waits for a reply and parses it"""
    time_left = timeout
    
    while True:
        start_time = time.time()
        what_ready = select.select([mySocket], [], [], time_left)
        time_in_select = (time.time() - start_time)
        
        if what_ready[0] == []:  # Timeout
            # ***FIX: Return a dict, not a string***
            return {"status": "timeout", "err": "Request timed out."}

        time_received = time.time()
        # TODO: read the packet and parse the source IP address, you will need this part for traceroute
        recPacket, (src_ip, _port) = mySocket.recvfrom(1024)

        ip_header = recPacket[0:20]
        ip_header_len = (ip_header[0] & 0x0F) * 4 
        ttl = ip_header[8] 
        
        icmp_packet = recPacket[ip_header_len:]
        icmp_header = icmp_packet[0:8]
        icmp_type, icmp_code, _checksum, rcv_id, rcv_seq = struct.unpack("bbHHh", icmp_header)
        
        result = {
            "status": None, "ts_recv": time_received, "src_ip": src_ip,
            "ttl": ttl, "icmp_type": icmp_type, "icmp_code": icmp_code,
            "err": None, "rtt_ms": None
        }
        
        # TODO: calculate and return the round trip time for this ping
        if icmp_type == ICMP_ECHO_REPLY:
            if rcv_id == ID and rcv_seq == seq:
                data_payload = icmp_packet[8:]
                if len(data_payload) >= 8:
                    send_time = struct.unpack("d", data_payload[0:8])[0]
                    rtt = (time_received - send_time) * 1000
                    
                    result.update({"status": "reply", "rtt_ms": rtt})
                    return result

        # TODO: handle different response type and error code, display error message to the user
        elif icmp_type == ICMP_DEST_UNREACHABLE or icmp_type == ICMP_TIME_EXCEEDED:
            
            # An error packet includes the original packet's IP header and 
            # the first 8 bytes of its payload. We need to find our original ICMP header to see if this error is for us.
            
            # Find the start of the original IP header.
            # It's located after the outer IP header ip_header_len and the 8-byte ICMP error header.
            inner_ip_header_offset = ip_header_len + 8
            inner_ip_header = recPacket[inner_ip_header_offset : inner_ip_header_offset + 20]
            inner_ip_header_len = (inner_ip_header[0] & 0x0F) * 4
            
            # Now find the start of the original ICMP header
            inner_icmp_header_offset = ip_header_len + 8 + inner_ip_header_len
            inner_icmp_header = recPacket[inner_icmp_header_offset : inner_icmp_header_offset + 8]
            
            # Unpack the original ID and sequence number
            _orig_type, _orig_code, _, orig_id, orig_seq = struct.unpack("bbHHh", inner_icmp_header)
            
            # Check if this error message corresponds to the ping we just sent
            if orig_id == ID and orig_seq == seq:
                err_str = get_icmp_error_str(icmp_type, icmp_code)
                result.update({"status": "error", "err": err_str})
                return result

        # If the packet we received was a reply, but not for us (wrong ID/seq),
        # or some other ICMP type, we loop again, and reduce the timeout.
        time_left = time_left - time_in_select
        if time_left <= 0:
            return {"status": "timeout", "err": "Request timed out."}


def ping(target: str,
         count: int,
         interval: float,
         timeout: float,
         json_file_path: str,
         qps_limit: float,
         no_color: bool,
         i_accept_the_risk_flag: bool):
    """
    Performs ICMP ping and prints statistics.
    """
    #ethics and safety check
    if interval < (1 / qps_limit) and not i_accept_the_risk_flag:
        print("Error: Probe rate > 1 QPS. Use --i-accept-the-risk to override.", file=sys.stderr)
        sys.exit(1)

    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"Error: Cannot resolve host {target}: {e}")
        return

    print(f"PING {target} ({dest_ip})")
        
    my_socket = None

    try:
        icmp = socket.getprotobyname("icmp")
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except Exception as e:
        print(f"Failed to create socket: {e}")
        print("run with 'sudo'!")
        sys.exit(1)


    my_id = os.getpid() & 0xFFFF
    
    packets_sent = 0
    packets_lost = 0
    stats = OnlineStats() 
    
    json_file = None

    try:
        for i in range(count):
            seq = i + 1 
            packets_sent += 1
            
            # Send ping
            ts_send = send_one_ping(my_socket, dest_ip, my_id, seq)
            
            # receive ping
            result = receive_one_ping(my_socket, my_id, timeout, dest_ip, seq)
            
            json_data = {
                "tool": "ping", "ts_send": ts_send, "ts_recv": result.get("ts_recv"),
                "dst": target, "dst_ip": dest_ip, "seq": seq,
                "ttl_reply": result.get("ttl"), "rtt_ms": result.get("rtt_ms"),
                "icmp_type": result.get("icmp_type"), "icmp_code": result.get("icmp_code"),
                "err": result.get("err")
            }

            jwrite(json_file_path, json_data)

            status = result.get("status")
            
            if status == "reply":
                rtt = result.get('rtt_ms')
                ttl = result.get('ttl')
                stats.add(rtt)
                print(f"Reply from {dest_ip}: seq={seq} ttl={ttl} rtt={rtt:.2f} ms")
                
            elif status == "timeout":
                packets_lost += 1
                print(f"Request timed out for seq={seq}")
                
            elif status == "error":
                packets_lost += 1
                err_str = result.get('err', 'Unknown error')
                src_ip = result.get('src_ip', 'unknown')
                ttl = result.get('ttl', 'N/A')
                print(f"Error from {src_ip}: seq={seq} ttl={ttl} ({err_str})")
            

            if i < (count - 1):
                time.sleep(interval)

    finally:
        if my_socket:
            my_socket.close()
        if json_file:
            json_file.close()

    # Print Summary Statistics
    loss_percent = (packets_lost / packets_sent) * 100 if packets_sent > 0 else 0
    
    print(f"\n--- {target} ping statistics ---")
    print(f"{packets_sent} packets transmitted, {packets_sent - packets_lost} received, {loss_percent:.1f}% packet loss")

    if stats.n > 0:
        summary = stats.summary()
        print(f"rtt min/avg/max/stddev = {summary['min']:.3f}/{summary['avg']:.3f}/{summary['max']:.3f}/{summary['stddev']:.3f} ms")


def main():
    parser = argparse.ArgumentParser(description="ICMP Ping")
    parser.add_argument("target", help="Hostname or IP to ping")
    parser.add_argument("--count", "-c", type=int, default=4, help="Number of probes to send")
    parser.add_argument("--interval", "-i", type=float, default=1.0, help="Interval between probes (s)")
    parser.add_argument("--timeout", "-t", type=float, default=1.0, help="Per-probe timeout (s)")
    parser.add_argument("--json", type=str, help="Write per-probe results to JSONL file")
    parser.add_argument("--qps-limit", type=float, default=1.0,
                        help="Max probe rate (queries per second)")
    parser.add_argument("--no-color", action="store_true", help="Disable color in output")
    parser.add_argument("--i-accept-the-risk", 
                        action="store_true", 
                        help="Allow probe rate > 1 QPS")
    args = parser.parse_args()

    print(f"Pinging {args.target} with count={args.count}, interval={args.interval}s")
    
    ping(target=args.target,
         count =args.count,
         interval=args.interval,
         timeout=args.timeout,
         json_file_path=args.json, 
         qps_limit=args.qps_limit,
         no_color=args.no_color,
         i_accept_the_risk_flag=args.i_accept_the_risk
        )

if __name__ == "__main__":
    main()