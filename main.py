import os
import time
import fcntl
import torch
import hashlib
import logging
import datetime
import classifier
import numpy as np
import socket, sys
from struct import *
from threading import Timer
import multiprocessing as mp
from pathlib import Path

FIRST_N_PKTS = 8
FIRST_N_BYTES = 80
BENIGN_IDX = 10

PKT_CLASSIFIER = classifier.CNN_RNN()
PKT_CLASSIFIER.load_state_dict(torch.load("pkt_classifier.pt", map_location=torch.device("cpu")))
PKT_CLASSIFIER.eval()

# def getflags( packet ):
#     # URG = packet & 0x020
#     # URG >>= 5
#     # ACK = packet & 0x010
#     # ACK >>= 4
#     # PSH = packet & 0x008
#     # PSH >>= 3
#     # RST = packet & 0x004
#     # RST >>= 2
#     # SYN = packet & 0x002
#     # SYN >>= 1
#     FIN = packet & 0x001
#     FIN >>= 0

#     return FIN
    
def get_key(pkt):
    key = ''
    # is_tcp_udp = False

    eth_length = 14
    eth_header = pkt[: eth_length]
    eth = unpack( '!6s6sH' , eth_header )
    eth_protocol = socket.ntohs( eth[2] )

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
	    # Parse IP header
	    # take first 20 characters for the ip header
        ip_header = pkt[eth_length: 20+eth_length]
		
	    # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]
        s_addr = socket.inet_ntoa( iph[8] )

        d_addr = socket.inet_ntoa( iph[9] )

        key += "s_addr " + str( s_addr ) + " d_addr " + str( d_addr ) + ' '
        
        # TCP protocol
        if protocol == 6:
            # check_protocol = True

            t = iph_length + eth_length
            tcp_header = pkt[t: t+20]
            
            # now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            FIN_FLG = getflags(tcph[5])

            key += "s_port " + str( source_port ) + " d_port " + str( dest_port )

        #ICMP Packets
        # elif protocol == 1:
            # check_protocol = True

            # u = iph_length + eth_length
            # icmph_length = 4
            # icmp_header = packet[u:u+4]

            # now unpack them :)
            # icmph = unpack( '!BBH' , icmp_header ) 
            
            # icmp_type = icmph[0]
            # code = icmph[1]
            # checksum = icmph[2]
        
        # UDP packets
        elif protocol == 17 :
            # check_protocol = True

            u = iph_length + eth_length
            udp_header = pkt[u:u+8]

            # now unpack them :)
            udph = unpack( '!HHHH' , udp_header )
            
            source_port = udph[0]
            dest_port = udph[1]

            key += "s_port " + str( source_port ) + " d_port " + str( dest_port )

        #some other IP packet like IGMP
        # else :
        #     print( 'Protocol other than TCP/UDP/ICMP' )

    # return key, check_protocol, FIN_flg
    return key

def pkt2nparr(flow):
    pkt_content = []

    for nth_pkt in range(min(len(flow), FIRST_N_PKTS)):
        idx = 0
        for pkt_val in flow[nth_pkt]:
            if idx == 80:
                break
            pkt_content.append(pkt_val)
            idx += 1
        if idx < 80:
            while idx != 80:
                pkt_content.append(0)
                idx += 1

        if nth_pkt == (len(flow) - 1) and nth_pkt < FIRST_N_PKTS-1:
            while nth_pkt != FIRST_N_PKTS-1:
                for _ in range(FIRST_N_BYTES):
                    pkt_content.append(0)
                nth_pkt += 1
    # for end

    pkt2np = np.array(pkt_content).reshape(1, 8, 80)
    
    return pkt2np

def classify_pkt(flow, key):
    dealt_flow = pkt2nparr(flow)

    flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
    output = PKT_CLASSIFIER(flow2tensor)
    _, predicted = torch.max(output, 1)
    
    print(f"\npredicted: {predicted}\n")

    
    log_filename = datetime.datetime.now().strftime(f"%Y-%m-%d_%H_%M_%S__{key}.log")
    logging.basicConfig(level=logging.INFO, filename="./log_file/" + log_filename, filemode='w',
	                    format='[%(asctime)s] %(message)s',
	                    datefmt='%Y%m%d %H:%M:%S',
    )
    logging.warning(key)

def generate_proc(flow, key):
    p = mp.Process(target=classify_pkt, args=(flow, key, ), daemon=True)
    p.start()

# def hash_key(key, proc_create_amt):
#     new_key = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16) % proc_create_amt
    
#     return new_key

if __name__ == "__main__":
    # open a socket
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs( 0x0003 ) )
    except socket.error as e:
        print( e )
        sys.exit()

    # create the log file directory if path is not exist
    Path("./log_file").mkdir(parents=True, exist_ok=True)
    flows = {}
    timers = {}
    
    recv_pkt_amt = 0
    while True:
        if recv_pkt_amt >= 50:
            break

        packet = s.recvfrom( 65565 )
        pkt = packet[0]
        # (key, check_protocol, FIN_flg) = get_key(pkt)
        key = get_key(pkt)

        recv_pkt_amt += 1

        # if check_protocol == False:
        #     continue
        if len( key ) != 0 and flows.get( key ) == None:
            flows[key] = [ pkt ]
            timers[key] = Timer(1.0, generate_proc, (flows[key], key))
            timers[key].start()
        else:
            timers[key].cancel()

            if len( flows[key] ) == 8:
                # do classification
                generate_proc(flows[key], key)
            elif len(flows[key]) > 8:
                # if FIN_flg == 1:
                #     del flows[key]
                continue
            else:
                flows[key].append( pkt )
                timers[key] = Timer( 1.0, generate_proc, (flows[key], key) )
                timers[key].start()

    time.sleep(1)
