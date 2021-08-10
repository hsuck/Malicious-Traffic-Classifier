import socket, sys
from struct import *
from threading import Timer
import os
import multiprocessing as mp
import hashlib
# import torch
import logging
import datetime
# import numpy as np
import time
import classifier


FIRST_N_PKTS = 8
FIRST_N_BYTES = 80
BENIGN_IDX = 10

PKT_CLASSIFIER = classifier.CNN_RNN()
PKT_CLASSIFIER.load_state_dict(torch.load("pkt_classifier.pt", map_location=torch.device("cpu")))
PKT_CLASSIFIER.eval()


def get_key(pkt):
    key = ''

    eth_length = 14
    eth_header = pkt[: eth_length]
    eth = unpack( '!6s6sH' , eth_header )
    eth_protocol = socket.ntohs( eth[2] )
    # print( ' Protocol : ' + str( eth_protocol ) )

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
            t = iph_length + eth_length
            tcp_header = pkt[t: t+20]

            # now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]

            key += str( source_port ) + ' ' + str( dest_port )

        # UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udp_header = pkt[u:u+8]

            # now unpack them :)
            udph = unpack( '!HHHH' , udp_header )
            
            source_port = udph[0]
            dest_port = udph[1]

            key += "s_port " + str( source_port ) + " d_port " + str( dest_port )

        #some other IP packet like IGMP
        else :
            print( 'Protocol other than TCP/UDP/ICMP' )
    
    return key

def pkt2nparr(flow):
    pkt_content = []

    for nth_pkt in range(min(len(flow), FIRST_N_PKTS)):
        idx = 0
        # print(type(flow[nth_pkt]))
        for pkt_val in flow[nth_pkt]:
            if idx == 80:
                break
            pkt_content.append(pkt_val)
            # print(pkt_val, end=' ')
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
    print("key now: " + str(key))
    dealt_flow = pkt2nparr(flow)

    flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
    output = PKT_CLASSIFIER(flow2tensor)
    _, predicted = torch.max(output, 1)
    print(output)
    print(predicted)
    
    # log_filename = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S.log")
    # logging.basicConfig(level=logging.INFO, filename=log_filename, filemode='w',
	#                     format='[%(asctime)s] %(message)s',
	#                     datefmt='%Y%m%d %H:%M:%S',
    # )
    # logging.warning(key)

def generate_proc(flow, key):
    p = mp.Process(target=classify_pkt, args=(flow, key, ))
    p.start()

def hash_key(key, proc_create_amt):
    new_key = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16) % proc_create_amt
    
    return new_key

if __name__ == "__main__":
    # open a socket
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs( 0x0003 ) )
    except socket.error as e:
        print( e )
        sys.exit()

    proc_create_amt = os.cpu_count() - 1
    flows = {}
    timers = {}
    
    recv_pkt_amt = 0
    while True:
        if recv_pkt_amt == 50:
            break

        key = ''

        packet = s.recvfrom( 65565 )

        start = time.time()
        pkt = packet[0]

        key = get_key(pkt)

        # breakpoint()
        if len( key ) != 0 and flows.get( key ) == None:
            flows[key] = [ pkt ]
            timers[key] = Timer(1.0, generate_proc, (flows[key], key))
            timers[key].start()
        else:
            flows[key].append( pkt )
            timers[key].cancel()

            if len( flows[key] ) == 8:
                # do classification
                generate_proc(flows[key], key)
            else:
                timers[key] = Timer( 1.0, generate_proc, (flows[key], key) )
                timers[key].start()

        end = time.time()

        print( "Time interval" + ( end - start ) )
    
        recv_pkt_amt += 1
