import numpy as np
import torch
from torch import nn
from torch import optim
from sklearn.model_selection import train_test_split
import classifier, train

FLOW_TYPES = ["Cridex", "Geodo", "Htbot", "Miuref", "Neris", "Nsis-ay", "Shifu",
             "Tinba", "Virut", "Zeus", "Benign"]
CUDA = False

def main():
    global CUDA
    device, CUDA = train.check_device()
    print("Using {} device".format(device))
    
    # load preprocessed data
    data_x = np.load("E:/CCU/topic/pcap_files/shuffled_x.npy")
    data_y = np.load("E:/CCU/topic/pcap_files/shuffled_y.npy")
    
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
    
    # import classifier
    PKT_CLASSIFIER = classifier.CNN_RNN().to(device)
    print(f"Model architecture:\n{PKT_CLASSIFIER}\n")

    # set arguments
    EPOCH = 10
    optimizer = optim.Adam(PKT_CLASSIFIER.parameters())

    PKT_CLASSIFIER.train()
    PKT_CLASSIFIER.float()
    train.train_step(PKT_CLASSIFIER, EPOCH, optimizer, CUDA, device)
# main()
if __name__ == "__main__":
    main()