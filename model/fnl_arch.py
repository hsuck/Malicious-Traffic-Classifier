#!/usr/bin/env python
# coding: utf-8

import numpy as np
import torch
from torch import nn
from torch import optim
from sklearn.model_selection import train_test_split


# Get cpu or gpu device for training.
if torch.cuda.is_available():
    device = "cuda"
    CUDA = True
else:
    device = "cpu"

print("Using {} device\n".format(device))

data_x_1 = np.load("flow_8pkts_80bytes.npy")
data_y_1 = np.load("flow_bothtypes_without_encoded.npy")
data_x_2 = np.load("flow_ext_x.npy")
data_y_2 = np.load("flow_ext_y.npy")
data_x = np.concatenate((data_x_1, data_x_2), axis=0)
data_y = np.concatenate((data_y_1, data_y_2), axis=0)

np.random.seed(42)
np.random.shuffle(data_x)
np.random.seed(42)
np.random.shuffle(data_y)

X_train, X_test, y_train, y_test = train_test_split(
        data_x_1, data_y_1, test_size=0.25, random_state=42
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

optimizer = optim.Adam(cnn_rnn.parameters())

def train_step(EPOCH, model):
    
    model.train()

    for epoch in range(EPOCH):
        
        running_loss = 0.0
        for batch_idx, (x, y) in enumerate(train_loader):
            x = x.float()
            y = y.to(device=device, dtype=torch.int64)

            if CUDA:
                x, y = x.to(device), y.to(device)
            optimizer.zero_grad()

            # forward + backward 
            outputs = model(x)
            
            loss = nn.functional.nll_loss(outputs, y)
            loss.backward()

            # update parameters
            optimizer.step()

            running_loss += loss.item()
            if batch_idx % 5000 == 4999:
                print("[%d, %5d] loss: %.3f" % (epoch+1, batch_idx+1, running_loss / 5000))
                running_loss = 0.0

EPOCH = 10
cnn_rnn.float()

import datetime

print(datetime.datetime.now())
train_step(EPOCH, cnn_rnn)
print(datetime.datetime.now())

# Save model

torch.save(cnn_rnn.state_dict(), "pkt_classifier.pt")

def test_step(model):
    
    model.eval()
    total = 0 
    test_loss = 0
    correct = 0
    
    with torch.no_grad():
        for x, y in test_loader:
            x = x.float()
            y = y.to(device=device, dtype=torch.int64)

            x, y = x.cuda(), y.cuda()

            outputs = model(x)
            _, predicted = torch.max(outputs, 1)

            total += y.shape[0]
            correct += torch.eq(predicted, y).sum().item()
    
            test_loss += nn.functional.nll_loss(outputs, y).data # sum up the batch loss 
    
    test_loss /= len(test_loader.dataset)
    print('\nTest set: Average loss: {:.4f}\n'.format(test_loss))
    acc_rate = correct / total
    print("acc: %.4f %%" % (acc_rate*100))

test_step(cnn_rnn)

# Load model
model = CNN_RNN().to(device)
model.load_state_dict(torch.load("pkt_classifier.pt"))
model.eval()

