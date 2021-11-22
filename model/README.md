# model.py
## 程式執行流程
* 設定是否使用gpu (line 13~19)
* 把資料集讀到程式 (line 21~22)
* 將資料集分為訓練集與測試集，比例為3:1。(line 51~53)
* 將資料放到pytorch的data loader，而訓練集有設定batch size為32 (line 55~65)
* 定義model (line 72~105)
* 定義訓練步驟 (line 113~148)
* 開始訓練 (line 154)
* 定義測試步驟 (line 163~207)
* 儲存訓練好的model (line 214)
* 定義繪製[confusion matrix](https://github.com/wcipriano/pretty-print-confusion-matrix)的函式 (line 223~405)
* 計算accuracy, precision跟recall (line 414~425)

## [將pcap file依照session/flow做分割](https://github.com/yungshenglu/USTC-TK2016)
執行第一步驟的指令時需要使未通過簽證的檔案的執行政策為非限制，因此需要以下指令來bypass
```
PowerShell.exe -ExecutionPolicy UnRestricted -File .runme.ps1
```
[PowerShell usage ref.](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)
