#!/usr/bin/env python
# coding: utf-8

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import torch
from torch import nn
from scapy.all import *
import os

ALL_Layer_dataset_path = "E:/CCU/topic/USTC_TFC2016/USTC-TK2016-master/2_Session/AllLayers/"

cur_path = os.walk(ALL_Layer_dataset_path)
pkts_amt = 0

for root, directories, files in cur_path:
    pkts_amt = pkts_amt + len(files)

print(pkts_amt)

N_PKTS = 8        # first n_pkts packets of the flow
N_BYTES = 80      # first n_bytes of the packet
N_TYPES = 11    # amount of the types of all the packets

# declare by np.zeros means padding with zeros at the same time
data_x = np.zeros(shape=(pkts_amt, N_PKTS, N_BYTES), dtype=int)
# data_y = np.zeros(shape=(pkts_amt, maltypes_amt), dtype=int)
data_y = np.zeros(shape=(pkts_amt), dtype=int)

def set_data(file_idx, _in_file, mal_type):
    pcap_in = sniff(count=N_PKTS, offline=ALL_Layer_dataset_path
                    + _append_path[mal_type] + _in_file)
    
    byte_pos = 0 # record the probe reading input now
    
    # fill the data_x
    for nth_packet in range(N_PKTS):
        byte_pos = 0 # reset the byte_pos for next packet
        for byte_val in raw(pcap_in[nth_packet]):
            data_x[file_idx, nth_packet, byte_pos] = byte_val
            byte_pos = byte_pos+1

            # case the packet is shorter than N_BYTES bytes
            # and the byte_pos is at the end
            if len(pcap_in[nth_packet]) < N_BYTES and byte_pos == len(pcap_in[nth_packet]):
                break
            
            # case the byte_pos is beyond the n_bytes
            if byte_pos >= N_BYTES:
                break
        
        # case the flow is shorter than N_PKTS and at the last packet
        if len(pcap_in) < N_PKTS and nth_packet == (len(pcap_in)-1):
            break
        
    # set the data_y
    data_y[file_idx] = mal_type

# set data_y without encoding
cur_path = os.walk(ALL_Layer_dataset_path)
file_idx = 0
mal_type = -1 # -1 for bypassing the situation of in the first directory
append_path_idx = 0
have_file = False
_append_path = []

for root, directories, files in cur_path:
    
    # set the path
    for directory in directories:
        _append_path.append(directory + '/')

    mal_type += 1
    
    # traverse the data only when there exists data
    for file in files:
        set_data(file_idx, file, mal_type-1)
        have_file = True
        
        file_idx = file_idx+1
    
    # bypass the situation when entering the specific path
    if have_file:
#         append_path_idx += 1
        have_file = False
#         print(f"_append_path[{mal_type-1}]: " + _append_path[mal_type-1])
        print("parsing {:.4f}%" .format((file_idx/pkts_amt)*100))

# Deal with Benign Section
# cur_path = os.walk(ALL_Layer_dataset_path + "/benign")
# mal_type += 1

# for root, directories, files in cur_path:
#     for directory in directories:
#         _append_path.append("benign/" + directory + '/')
        
#     for file in files:
#         set_data(file_idx, file, mal_type, append_path_idx)
#         have_file = True
#         file_idx += 1
        
#     if have_file:
#         append_path_idx += 1
#         have_file = False
#         print("parsing {:.4f}%" .format((file_idx/pkts_amt)*100))

np.save("flow_ext_x.npy", data_x)
#np.save("flow_8_80_y.npy", data_y)
np.save("flow_ext_y.npy", data_y)
# np.savetxt("data_x.txt", data_x, fmt="%i")
# np.savetxt("data_y.txt", data_y, fmt="%i")
# data_x = np.loadtxt("data_x.txt")