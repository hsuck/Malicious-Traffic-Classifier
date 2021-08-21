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
import grp, pwd

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
            t = iph_length + eth_length
            tcp_header = pkt[t: t+20]
            
            # now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]

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

    return key

def pkt2nparr(flow):
    pkt_content = []

    for nth_pkt in range(min(len(flow), FIRST_N_PKTS)):
        idx = 0

        # get info of packet reading now
        for pkt_val in flow[nth_pkt]:
            if idx == 80:
                break
            
            pkt_content.append(pkt_val)
            idx += 1
        
        # if idx less than 80 after reading packet, then fill it with 0
        if idx < 80:
            while idx != 80:
                pkt_content.append(0)
                idx += 1

        # if nth_pkt is less than 8, then fill it with 0 too
        if nth_pkt == (len(flow) - 1) and nth_pkt < FIRST_N_PKTS-1:
            while nth_pkt != FIRST_N_PKTS-1:
                for _ in range(FIRST_N_BYTES):
                    pkt_content.append(0)

                nth_pkt += 1
    # for end

    pkt2np = np.array(pkt_content).reshape(1, 8, 80)
    
    return pkt2np

def classify_pkt(flow, key):

    ###
    t_start = time.process_time()
    ###
    dealt_flow = pkt2nparr(flow)

    flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
    output = PKT_CLASSIFIER(flow2tensor)
    _, predicted = torch.max(output, 1)
    # uid = pwd.getpwnam("user").pw_uid
    # gid = grp.getgrnam("user").gr_gid
    # os.chown("./log_file", uid, gid)
    # os.chown("./time_dir", uid, gid)

    # class 10 represents the benign flow
    if predicted[0] != 10:
        log_filename = datetime.datetime.now().strftime(f"%Y-%m-%d_%H_%M_%S__{key}.log")
        logging.basicConfig(level=logging.INFO, filename="./log_file/" + log_filename, filemode='w',
                            format='[%(asctime)s] %(message)s',
                            datefmt='%Y%m%d %H:%M:%S',
        )
        logging.warning(key)
    
    t_end = time.process_time()
    t_consume = t_end - t_start

    print(f"\n******\nt_consume: {t_consume}\n******\n")
    _log_filename = str(t_consume*1000)
    logging.basicConfig(level=logging.INFO, filename="./time_dir/" + _log_filename, filemode='w',
                        format='[%(asctime)s] %(message)s',
                        datefmt='%Y%m%d %H:%M:%S',
    )
    logging.warning(t_consume)

def generate_proc(flow, key):
    p = mp.Process(target=classify_pkt, args=(flow, key, ), daemon=True)
    p.start()

    flow.clear()

if __name__ == "__main__":
    # open a socket
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs( 0x0003 ) )
    except socket.error as e:
        print( e )
        sys.exit()

    
    # mkdir for log time consumimg
    Path("./time_dir").mkdir(parents=True, exist_ok=True)
    
    # create the log file directory if path is not exist
    Path("./log_file").mkdir(parents=True, exist_ok=True)


    flows = {}
    timers = {}
    recv_pkt_amt = 0

    ###
    # t_key = 0
    # t_proc = 0
    # t_while_s = time.process_time()
    ###
    while True:
        if recv_pkt_amt >= 100:
            break
        
        packet = s.recvfrom( 65565 )
        pkt = packet[0]

        ###
        # t_key_s = time.process_time()
        ###
        key = get_key(pkt)
        ###
        # t_key_e = time.process_time()
        # t_key += (t_key_e - t_key_s)
        ###

        recv_pkt_amt += 1

        if len( key ) != 0 and flows.get( key ) == None:
            flows[key] = [ pkt ]
            timers[key] = Timer(1.0, generate_proc, (flows[key], key))
            timers[key].start()
        elif len( key ) != 0:
            timers[key].cancel()

            if len( flows[key] ) == 8:
                # do classification
                # t_proc_s = time.process_time()
                generate_proc(flows[key], key)
                # t_proc_e = time.process_time()
                # t_proc += ( t_proc_e - t_proc_s )
            else:
                flows[key].append( pkt )
                timers[key] = Timer( 1.0, generate_proc, (flows[key], key) )
                timers[key].start()

    ###
    # t_while_e = time.process_time()
    # print("****************")
    # print(f"average get key time: {(t_key / recv_pkt_amt) * 1000}")
    # print( f"Average open process time: { ( t_proc / recv_pkt_amt ) * 1000 }" )
    # print((t_while_e - t_while_s)*1000, end="\n****************\n")
    ###