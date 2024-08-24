import socket
import struct
import textwrap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '


DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '



def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind(("192.168.10.125", 0)) 
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nETHERNET FRAME: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        
        
        # 8 for ipv4
        if eth_proto == 8:
            (version, header_lenght, ttl, proto, src, target, data) = IPV4_packet(data)
            print(TAB_1 + 'IPV4 Packet')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL {}'.format(version, header_lenght, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target {}'.format(proto, src, target))
            
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + ' Data: ')
                print(format_multi_line(DATA_TAB_3, data))
            
            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port {}, Destination Port {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
                
                
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
            
            # others
            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))
        
        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB_2, data))
                
    

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return mac_addr(dest_mac), mac_addr(src_mac), socket.htons(proto), data[14:]

def mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr).upper()



#unpcking the ipv4 packet
def IPV4_packet(data):
    version_header_lenght = data[0]
    version = version_header_lenght >> 4
    header_lenght = (version_header_lenght & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_lenght, ttl, proto, ipv4(src), ipv4(target), data[header_lenght:]



def ipv4(addr):
    return '.'.join(map(str, addr))


#this part of the code unpacks the icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]




# unpack the TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) *4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


#unpacck the UDP segment
def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


#format multi_line data
def format_multi_line(prefix, string,size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])




main()






















