# Malicious-Traffic-Classifier
## Table of contents
* [Platforms](#platforms)
* [Dependencies](#Dependencies)
* [Execution](#Execution)
* [Execution flow](#Execution flow)
## Platforms
You should be able to execute the program on the following platforms:
* Ubuntu 20.04
## Dependencies
* The proper version of nvidia drivers if you'd like to use the cuda device. (You could refer to this [website](https://linuxconfig.org/how-to-install-the-nvidia-drivers-on-ubuntu-20-04-focal-fossa-linux))
* The latest version of numpy (1.21.1 or greater)
* The latest version of [pytorch](https://pytorch.org/) **with compute platform on CUDA 10.2/11.3**
## Execution
To execute the program, you should create a new environment used to install all package in need first. 
```
virtualenv your_env_name
```
This command will create a virtual environment upon the directory where you run the command. Once you've created a virtual environment, you may activate it.
```
source your_env_name/bin/activate
```
Install dependencies
```
pip3 install -r requirement.txt
```
Finally, after installing all packages listed above, you'll be able to execute the program with an argument specified the network interface.
```
python3 main.py network_interface_name
```

## Execution flow
* main()
    * 開一個用來接收封包的 socket (line 257).
    * 如果在執行程式時有提供網卡的名稱，我們會限制 socket 只透過那張網卡收錄封包。(line 261 to 269)
    * 設定 log file 的輸出格式。 (line 276 to 289)
    * 產生用來分類封包的 daemon process。(line 300 to 306)
    * 開始擷取封包 (line 323 to 346)
        * 產生每個封包的 key (line 329)
            * get_key() 函數 (line 41) 會提取封包中的 protocol, 來源/目的地位址與 port 號去產生 key，最後再回傳。
        * 檢查封包的 key 是否已經存在在儲存的資料結構中。如果沒有的話便設置一個 timer 給這個封包並且將其儲存，否則會檢查儲存封包的資料結構中是否包含 8 個封包。如果包含 8 個封包則將這個 flow 藉由 pass_pkt2proc() (line 249) 傳給 process 去做分類，否則會把封包存到資料結構中並且重設 Timer (line 333 to 336)
            * pass_pkt2proc() 函數會將資料藉由 multiprocessing 函數庫中的 Queue 傳遞給 process，並且把儲存該 flow 的資料結構中的封包刪除。 (line 249 to 254)
* classify_proc() 函數定義了 forked process 所要執行的程式。 (line 163 to 247)
    * 首先他會檢查是否能取得 cuda 裝置。如果能的話便會將訓練好的 model 引入到 cuda 裝置中。 (line 164 to 171)
    * 然後便會用一個 for 迴圈來不斷地取得 main process 的資料。 (line 176 to 246)
        * for 迴圈會一直不斷的從 Queue 中讀資料直到取得了特定字串。(line 176)
        * 將 flow 轉成 numpy array 型態。(line 181 jump to line 124)
            * pkt2nparr() 函數 (line 124) 會把封包的每個 byte 值讀出後儲存。如果擷取的 flow 的長度不夠長，我們會將剩餘的空間補 0。最後函數會回傳一個 (1, 8, 80) 的 numpy array。
        * 將處理過後的 flow 轉成 tensor 後，然後把他放到 cuda 裝置中 (如果沒有的話會放到 cpu)。最後把他傳給分類器去分類。 (line 190, 191 and 199).
        * 取得預測結果 (line 207).
        * 如果預測結果不為良性的我們會以 json format 輸出包含協定，來源/目的地位址與 port 號，攻擊型態與此 flow 的長度的資訊到 log file。 (line 226 to 238)
