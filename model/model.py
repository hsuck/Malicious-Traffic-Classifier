#!/usr/bin/env python
# coding: utf-8

import numpy as np
import torch
from torch import nn
from torch import optim
from sklearn.model_selection import train_test_split

FLOW_TYPES = ["Cridex", "Geodo", "Htbot", "Miuref", "Neris", "Nsis-ay", "Shifu", "Tinba", "Virut", "Zeus", "Benign"]

# Get cpu or gpu device for training.
if torch.cuda.is_available():
    device = "cuda"
    CUDA = True
else:
    device = "cpu"

print("Using {} device".format(device))

data_x = np.load("E:/CCU/topic/pcap_files/shuffled_x.npy")
data_y = np.load("E:/CCU/topic/pcap_files/shuffled_y.npy")

# generate the shuffled dataset
# data_x_1 = np.load("E:/CCU/topic/pcap_files/flow_8pkts_80bytes.npy")
# data_y_1 = np.load("E:/CCU/topic/pcap_files/flow_bothtypes_without_encoded.npy")
# data_x_2 = np.load("E:/CCU/topic/pcap_files/flow_ext_x.npy")
# data_y_2 = np.load("E:/CCU/topic/pcap_files/flow_ext_y.npy")
# data_x = np.concatenate((data_x_1, data_x_2), axis=0)
# data_y = np.concatenate((data_y_1, data_y_2), axis=0)
# np.random.seed(42)
# np.random.shuffle(data_x)
# np.random.seed(42)
# np.random.shuffle(data_y)

# save the data
# np.save("E:/CCU/topic/pcap_files/shuffled_x.npy", data_x)
# np.save("E:/CCU/topic/pcap_files/shuffled_y.npy", data_y)
# np.save("shuffled_y1.npy", data_y[0:1200000])
# np.save("shuffled_y2.npy", data_y[1200000:])

# print(data_x.shape)
# print(data_y.shape)

# check the proportion of each type
# for i in range(11):
#     print(FLOW_TYPES[i],end=": ")
#     print("{:.2f} %".format(np.sum(data_y == i)/1554142))

# load data to the pytorch data loader
X_train, X_test, y_train, y_test = train_test_split(
        data_x, data_y, test_size=0.25, random_state=42
    )

train_dataset = torch.utils.data.TensorDataset(torch.from_numpy(X_train),
                                               torch.from_numpy(y_train))

train_loader = torch.utils.data.DataLoader(dataset=train_dataset,
                                           batch_size = 32,
                                           shuffle = True)

test_dataset = torch.utils.data.TensorDataset(torch.from_numpy(X_test),
                                               torch.from_numpy(y_test))

test_loader = torch.utils.data.DataLoader(dataset=test_dataset,
                                           shuffle = True)

# N_PKTS = 8        # first n_pkts packets of the flow
# N_BYTES = 80      # first n_bytes of the packet
# MALTYPES_AMT = 10 # amount of the types of the malicious packets

class CNN_RNN(nn.Module):
    def __init__(self):
        super(CNN_RNN, self).__init__()
        self.layers1 = nn.Sequential(
            nn.Conv2d(1, 32, kernel_size=(2, 4)),
            nn.MaxPool2d( kernel_size = ( 2, 3 ), stride = 1 ),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.Conv2d(32, 64, kernel_size=(2, 4)),
            nn.MaxPool2d( kernel_size = ( 2, 3 ), stride = 1 ),
            nn.BatchNorm2d(64),
            nn.ReLU(),
        )
        self.lstm5 = nn.LSTM(280, 100, batch_first = True)
        
        self.layers2 = nn.Sequential(
            nn.ReLU(),
            nn.Linear(6400, 100),
            nn.ReLU(),
            nn.Linear(100, 11),
        )
            
    def forward(self, x):
        x_in = x.view(x.size()[0], 1, x.size()[1], x.size()[2])
        x = self.layers1(x_in)
        x_in = x.view(x.size()[0], x.size()[1], -1)
        x_out, (h_n, c_n) = self.lstm5(x_in, None)
        x = x_out.contiguous().view(x_out.size()[0], -1)
        
        x_out = self.layers2(x)
#         output = torch.sigmoid(x_out)
        output = nn.functional.log_softmax(x_out, dim=1)
        
        return output

cnn_rnn = CNN_RNN().to(device)
print(cnn_rnn)

# criterion = nn.MultiLabelSoftMarginLoss()
optimizer = optim.Adam(cnn_rnn.parameters())

def train_step(EPOCH, model):
    
    model.train()

    for epoch in range(EPOCH):
        
        running_loss = 0.0
        for batch_idx, (x, y) in enumerate(train_loader):
            
            x = x.float()
            y = y.to(device=device, dtype=torch.int64)
            
#             y_one_hot = nn.functional.one_hot(y.long())
#             print(y_one_hot.shape)
#             print(x.shape)
            if CUDA:
#                 x, y_one_hot = x.to(device), y_one_hot.to(device)
                x, y = x.to(device), y.to(device)
            optimizer.zero_grad()

            # forward + backward 
#             breakpoint()
            outputs = model(x)
#             print(outputs.shape)
            
            loss = nn.functional.nll_loss(outputs, y)
#             loss = criterion(outputs, y_one_hot)
            loss.backward()

            # update parameters
            optimizer.step()

            running_loss += loss.item()
            if batch_idx % 5000 == 4999:
                print("[%d, %5d] loss: %.3f" % (epoch+1, batch_idx+1, running_loss / 5000))
                running_loss = 0.0

EPOCH = 10
cnn_rnn.train()
cnn_rnn.float()

train_step(EPOCH, cnn_rnn)

# check the duration of training
# import datetime

# print(datetime.datetime.now())
# train_step(EPOCH, cnn_rnn)
# print(datetime.datetime.now())

def test_step(model):
    
    model.eval()
    total = 0 
    test_loss = 0
    correct = 0
    all_preds = torch.tensor([])
    all_labels = torch.tensor([])
    
    with torch.no_grad():
        for x, y in test_loader:
            all_labels = torch.cat((all_labels, y), dim=0)
            
            x = x.float()
            y = y.long()
            # y_one_hot = nn.functional.one_hot(y.long(), num_classes=11)

            x, y = x.cuda(), y.cuda()
            # x, y_one_hot = x.cuda(), y_one_hot.cuda()

            outputs = model(x)
            _, predicted = torch.max(outputs, 1)
            all_preds = torch.cat((all_preds, predicted.cpu()), dim=0)

            total += y.shape[0]
            correct += torch.eq(predicted, y).sum().item()
            # correct += torch.eq(y_out, y).sum().item()
    
            test_loss += nn.functional.nll_loss(outputs, y).data # sum up the batch loss 
            # test_loss += criterion(outputs, y_one_hot)
    
    # get the confusion matrix
    stacked = torch.stack((all_preds, all_labels), dim=1)
    cf_matrix = np.zeros(shape=(11, 11))
    for p in stacked:
        tl, pl = p.tolist()
        cf_matrix[int(tl), int(pl)] += 1
    
    test_loss /= len(test_loader.dataset)
    acc_rate = correct / total
    
    print('\nTest set: Average loss: {:.4f}\n'.format(test_loss))
    print("acc: %.4f %%" % (acc_rate*100))
    
    return cf_matrix

# test the accuracy of the model,and get 
# the confusion matrix of the output
cf_matrix = test_step(cnn_rnn)

# Save model
torch.save(cnn_rnn.state_dict(), "pkt_classifier.pt")

# Load model
# pkt_classifier = CNN_RNN().to(device)
# pkt_classifier.load_state_dict(torch.load("pkt_classifier.pt"))
# model.eval()
# cf_matrix = test_step(pkt_classifier)

# draw the confusion matrix
import seaborn as sn
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.collections import QuadMesh
import matplotlib.font_manager as fm

def get_new_fig(fn, figsize=[11, 11]):
    """ Init graphics """
    fig1 = plt.figure(fn, figsize)
    ax1 = fig1.gca()   # Get Current Axis
    ax1.cla() # clear existing plot
    return fig1, ax1
#

def configcell_text_and_colors(array_df, lin, col, oText, facecolors, posi, fz, fmt, show_null_values=0):
    """
      config cell text and colors
      and return text elements to add and to dell
      @TODO: use fmt
    """
    text_add = []; text_del = [];
    cell_val = array_df[lin][col]
    tot_all = array_df[-1][-1]
    per = (float(cell_val) / tot_all) * 100
    curr_column = array_df[:,col]
    ccl = len(curr_column)

    # last line  and/or last column
    if(col == (ccl - 1)) or (lin == (ccl - 1)):
        # tots and percents
        if(cell_val != 0):
            if(col == ccl - 1) and (lin == ccl - 1):
                tot_rig = 0
                for i in range(array_df.shape[0] - 1):
                    tot_rig += array_df[i][i]
                per_ok = (float(tot_rig) / cell_val) * 100
            elif(col == ccl - 1):
                tot_rig = array_df[lin][lin]
                per_ok = (float(tot_rig) / cell_val) * 100
            elif(lin == ccl - 1):
                tot_rig = array_df[col][col]
                per_ok = (float(tot_rig) / cell_val) * 100
            per_err = 100 - per_ok
        else:
            per_ok = per_err = 0
        per_ok_s = ['%.2f%%'%(per_ok), '100%'] [int(per_ok == 100)]
        # text to DEL
        text_del.append(oText)

        # text to ADD
        font_prop = fm.FontProperties(weight='bold', size=fz)
        text_kwargs = dict(color='w', ha="center", va="center", gid='sum', fontproperties=font_prop)
        lis_txt = ['%d'%(cell_val), per_ok_s, '%.2f%%'%(per_err)]
        lis_kwa = [text_kwargs]
        dic = text_kwargs.copy(); dic['color'] = 'g'; lis_kwa.append(dic);
        dic = text_kwargs.copy(); dic['color'] = 'r'; lis_kwa.append(dic);
        lis_pos = [(oText._x, oText._y-0.3), (oText._x, oText._y), (oText._x, oText._y+0.3)]
        for i in range(len(lis_txt)):
            newText = dict(x=lis_pos[i][0], y=lis_pos[i][1], text=lis_txt[i], kw=lis_kwa[i])
            # print 'lin: %s, col: %s, newText: %s' %(lin, col, newText)
            text_add.append(newText)

        # set background color for sum cells (last line and last column)
        carr = [0.27, 0.30, 0.27, 1.0]
        if(col == ccl - 1) and (lin == ccl - 1):
            carr = [0.17, 0.20, 0.17, 1.0]
        facecolors[posi] = carr

    else:
        if(per > 0):
            txt = '%s\n%.4f%%' %(cell_val, per)
        else:
            if(show_null_values == 0):
                txt = ''
            elif(show_null_values == 1):
                txt = '0'
            else:
                txt = '0\n0.0%'
        oText.set_text(txt)

        # main diagonal
        if(col == lin):
            # set color of the textin the diagonal to white
            oText.set_color('w')
            # set background color in the diagonal to blue
            facecolors[posi] = [0.35, 0.8, 0.55, 1.0]
        else:
            oText.set_color('r')

    return text_add, text_del
#

def insert_totals(df_cm):
    """ insert total column and line (the last ones) """
    sum_col = []
    for c in df_cm.columns:
        sum_col.append( df_cm[c].sum() )
    sum_lin = []
    for item_line in df_cm.iterrows():
        sum_lin.append( item_line[1].sum() )
    df_cm['sum_lin'] = sum_lin
    sum_col.append(np.sum(sum_lin))
    df_cm.loc['sum_col'] = sum_col
#

def pretty_plot_confusion_matrix(df_cm, annot=True, cmap="Oranges", fmt='.2f', fz=11,
      lw=0.5, cbar=False, figsize=[11, 11], show_null_values=0, pred_val_axis='y'):
    """
      print conf matrix with default layout (like matlab)
      params:
        df_cm          dataframe (pandas) without totals
        annot          print text in each cell
        cmap           Oranges,Oranges_r,YlGnBu,Blues,RdBu, ... see:
        fz             fontsize
        lw             linewidth
        pred_val_axis  where to show the prediction values (x or y axis)
                        'col' or 'x': show predicted values in columns (x axis) instead lines
                        'lin' or 'y': show predicted values in lines   (y axis)
    """
    if(pred_val_axis in ('col', 'x')):
        xlbl = 'Predicted'
        ylbl = 'Actual'
    else:
        xlbl = 'Actual'
        ylbl = 'Predicted'
        df_cm = df_cm.T

    # create "Total" column
    insert_totals(df_cm)

    # this is for print allways in the same window
    fig, ax1 = get_new_fig('Conf matrix default', figsize)

    # thanks for seaborn
    ax = sn.heatmap(df_cm, annot=annot, annot_kws={"size": fz}, linewidths=lw, ax=ax1,
                    cbar=cbar, cmap=cmap, linecolor='w', fmt=fmt)

    # set ticklabels rotation
    ax.set_xticklabels(ax.get_xticklabels(), rotation = 45, fontsize = 10)
    ax.set_yticklabels(ax.get_yticklabels(), rotation = 25, fontsize = 10)

    # Turn off all the ticks
    for t in ax.xaxis.get_major_ticks():
        t.tick1On = False
        t.tick2On = False
    for t in ax.yaxis.get_major_ticks():
        t.tick1On = False
        t.tick2On = False

    # face colors list
    quadmesh = ax.findobj(QuadMesh)[0]
    facecolors = quadmesh.get_facecolors()

    # iter in text elements
    array_df = np.array( df_cm.to_records(index=False).tolist() )
    text_add = []; text_del = [];
    posi = -1 # from left to right, bottom to top.
    for t in ax.collections[0].axes.texts: #ax.texts:
        pos = np.array(t.get_position()) - [0.5, 0.5]
        lin = int(pos[1]); col = int(pos[0]);
        posi += 1
        # print ('>>> pos: %s, posi: %s, val: %s, txt: %s' %(pos, posi, array_df[lin][col], t.get_text()))

        # set text
        txt_res = configcell_text_and_colors(array_df, lin, col, t, facecolors, posi, fz, fmt, show_null_values)

        text_add.extend(txt_res[0])
        text_del.extend(txt_res[1])

    # remove the old ones
    for item in text_del:
        item.remove()
    # append the new ones
    for item in text_add:
        ax.text(item['x'], item['y'], item['text'], **item['kw'])

    # titles and legends
    ax.set_title('Confusion matrix')
    ax.set_xlabel(xlbl)
    ax.set_ylabel(ylbl)
    plt.tight_layout()  #set layout slim
    plt.show()
# pretty_plot_confusion_matrix

df_cm = pd.DataFrame(cf_matrix, index=FLOW_TYPES, columns=FLOW_TYPES)
pretty_plot_confusion_matrix(df_cm, fmt=".6f")
# df_cm.to_csv("confusion_matrix.csv")
# cf_matrix = np.load("confusion_matrix.npy", allow_pickle=True)
# print(cf_matrix)

# calculate the accuracy, precision and recall
for mal_types in range(cf_matrix.shape[0]):
    TP = cf_matrix[mal_types, mal_types]; FP = 0; FN = 0
    for _ in range(cf_matrix.shape[0]):
        if _ == mal_types:
            continue
        FP += cf_matrix[_, mal_types]
        FN += cf_matrix[mal_types, _]
        
    print(f"{FLOW_TYPES[mal_types]}")
    print("\tAccuracy: {:.4f}%".format((TP / (TP+FP+FN))*100))
    print("\tPrecision: {:.4f}%".format((TP / (TP+FP))*100))
    print("\tRecall: {:.4f}%".format((TP / (TP+FN))*100))