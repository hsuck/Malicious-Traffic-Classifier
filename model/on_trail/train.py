import torch
import numpy as np
from sklearn.model_selection import train_test_split

def check_device():
    has_cuda = False
    if torch.cuda.is_available():
        device = "cuda"
        has_cuda = True
    else:
        device = "cpu"
    
    return device, has_cuda
# check_device()

def data_preparation():
    # load preprocessed data
    data_x = np.load("E:/CCU/topic/pcap_files/shuffled_x.npy")
    data_y = np.load("E:/CCU/topic/pcap_files/shuffled_y.npy")
    
    # load data to the pytorch data loader
    X_train, X_test, y_train, y_test = train_test_split(
            data_x, data_y, test_size=0.25, random_state=42
        )
    train_dataset = torch.utils.data.TensorDataset(torch.from_numpy(X_train),
                                                torch.from_numpy(y_train))
    test_dataset = torch.utils.data.TensorDataset(torch.from_numpy(X_test),
                                                torch.from_numpy(y_test))

    train_loader = torch.utils.data.DataLoader(dataset=train_dataset,
                                            batch_size = 32,
                                            shuffle = True)
    test_loader = torch.utils.data.DataLoader(dataset=test_dataset,
                                            shuffle = True)

    return train_loader, test_loader
# data_preparation()

def train_step(model, EPOCH, optimizer, CUDA, device):
    
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