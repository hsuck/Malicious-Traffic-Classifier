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
import json
import signal

FIRST_N_PKTS = 8
FIRST_N_BYTES = 80
BENIGN_IDX = 10

# PKT_CLASSIFIER = classifier.CNN_RNN()
# PKT_CLASSIFIER.load_state_dict(torch.load("pkt_classifier.pt", map_location=torch.device("cpu")))
# PKT_CLASSIFIER.eval()

Lock = mp.Lock()

class JsonFilter(logging.Filter):
    s_addr = 's_addr'
    d_addr = 'd_addr'
    s_port = 's_port'
    d_port = 'd_port'
    c = 'class'
    num_pkts = 'num_pkts'

    def filter( self, record ):
        record.s_addr = self.s_addr
        record.d_addr = self.d_addr
        record.s_port = self.s_port
        record.d_port = self.d_port
        record.c = self.c
        record.num_pkts = self.num_pkts
        return True

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

        key += "s_addr " + str( s_addr ) + " d_addr " + str( d_addr )
        
        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = pkt[t: t+20]
            
            # now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]

            key += " s_port " + str( source_port ) + " d_port " + str( dest_port )

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

            key += " s_port " + str( source_port ) + " d_port " + str( dest_port )
    return key
# get_key()

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
# pkt2nparr()

def classify_proc(msg_queue, lock):
    PKT_CLASSIFIER = classifier.CNN_RNN()
    PKT_CLASSIFIER.load_state_dict(torch.load("pkt_classifier.pt", map_location=torch.device("cpu")))
    PKT_CLASSIFIER.eval()
    
    #
    Path("./time_dir").mkdir(parents=True, exist_ok=True)
    #
    for data in iter(msg_queue.get, "End of program."):
        [flow, key] = data
        # ###
        # t_start = time.process_time()
        # ###
        dealt_flow = pkt2nparr(flow)
        flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
        output = PKT_CLASSIFIER(flow2tensor)
        _, predicted = torch.max(output, 1)
        lock.acquire()

        logger = logging.getLogger("classifier")
        filter_ = JsonFilter()
        logger.addFilter( filter_ )
        inf = key.split(' ')
        if "s_addr" in inf:
            filter_.s_addr = inf[1]
            filter_.d_addr = inf[3]
            if "s_port" in inf:
                filter_.s_port = inf[5]
                filter_.d_port = inf[7]

        filter_.c = str( predicted[0] )
        filter_.num_pkts = len( flow )
        logger.info( key )

        lock.release()

        #
        # t_end = time.process_time()
        # t_consume = (t_end - t_start)*1000

        # print(f"t_consume: {t_consume}")
        # print(f"\n******\nt_consume: {t_consume}\n******\n")
        #
    # for
# classify_proc()

def decide_pkt_dest(key, proc_create_amt):
    new_key = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16)
    pkt_dest = new_key % proc_create_amt
    
    return pkt_dest
# decide_pkt_dest()

def pass_pkt2proc(key, flow, msg_q, proc_create_amt):
    # pkt_dest = decide_pkt_dest(key, proc_create_amt)
    pkt_dest = time.process_time_ns() % proc_create_amt
    # print(f"pkt_dest: {pkt_dest}")
    proc_now = 'p' + str(pkt_dest)
    msg_q[proc_now].put([flow.copy(), key])
    flow.clear()
# generate_proc()

def main():
    # open a socket
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs( 0x0003 ) )
    except socket.error as e:
        print( e )
        sys.exit()

    # create the log file directory if path is not exist
    Path("./log_file").mkdir(parents=True, exist_ok=True)
    log_filename = datetime.datetime.now().strftime(f"%Y-%m-%d.log")
    formate = json.dumps({"timestamp": "%(asctime)s.%(msecs)03d",
                          "source address": "%(s_addr)s",
                          "destination address": "%(d_addr)s",
                          "source port": "%(s_port)s",
                          "destination port": "%(d_port)s",
                          "class": "%(c)s",
                          "number of packets": "%(num_pkts)s"
    })
    logging.basicConfig(level=logging.INFO, filename="./log_file/" + log_filename, filemode='a',
                            format=formate,
                            datefmt='%Y/%m/%d %H:%M:%S'
    )
    cpu_amt_sub1 = os.cpu_count() - 1

    # create the processes to classifiy the packets
    procs = {}
    msg_q = {}
    for _ in range(cpu_amt_sub1):
        proc_now = 'p' + str(_)

        msg_q[proc_now] = mp.Queue()
        procs[proc_now] = mp.Process(target=classify_proc
                            , args=(msg_q[proc_now], Lock, ), daemon=False)
        procs[proc_now].start()
    # for loop

    def signal_handler(signum, frame):
        for _ in range(cpu_amt_sub1):
            proc_now = 'p' + str(_)
            msg_q[proc_now].put("End of program.")
            procs[proc_now].join()
    # signal_handler()

    # capture SIGINT signal to avoid the generating of the zombie processes
    signal.signal(signal.SIGINT, signal_handler)

    flows = {}
    timers = {}
    recv_pkt_amt = 0

    while True:
        # if recv_pkt_amt >= 10:
        #     break
        
        packet = s.recvfrom( 65565 )
        pkt = packet[0]
        key = get_key(pkt)

        recv_pkt_amt += 1

        if len( key ) != 0 and flows.get( key ) == None:
            flows[key] = [ pkt ]
            timers[key] = Timer(1.0, pass_pkt2proc, (key, flows[key], msg_q, cpu_amt_sub1))
            timers[key].start()
        elif len( key ) != 0:
            timers[key].cancel()

            if len( flows[key] ) == 8:
                # do classification
                pass_pkt2proc(key, flows[key], msg_q, cpu_amt_sub1)
            else:
                flows[key].append( pkt )
                timers[key] = Timer( 1.0, pass_pkt2proc, (key, flows[key], msg_q, cpu_amt_sub1))
                timers[key].start()
        # elif
    # while True

    # time.sleep( 1.1 )
    # for _ in range(cpu_amt_sub1):
    #     proc_now = 'p' + str(_)
    #     msg_q[proc_now].put("End of program.")
    #     procs[proc_now].join()
# main()

if __name__ == "__main__":
    main()