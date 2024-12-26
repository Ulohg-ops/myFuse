
此為中央資工新興記憶體課程LAB2 

## Objective: 
This assignment aims to deepen your understanding of file system operations and encryption mechanisms by building a simple in-memory file system using the FUSE (Filesystem in Userspace) framework, followed by integrating AES-256 encryption to ensure data security.

## Resources
1. Less Simple, Yet Stupid Filesystem (Using FUSE): https://github.com/MaaSTaaR/LSYSFS
2. In Storage Filesystem (ISFS) Using FUSE: https://github.com/yttty/isfs

## Outline
1. 可以完成基本功能的file system https://github.com/Ulohg-ops/myFuse/tree/main/encryptFileFuse
2. 除了基本功能以外在read/write的資料在傳輸過程也是加密的 https://github.com/Ulohg-ops/myFuse/tree/main/encryptFuse
3. 使用者必須要輸入密鑰才能open file https://github.com/Ulohg-ops/myFuse/tree/main/encryptFileFuse
4. 把金鑰儲存在檔案中 https://github.com/Ulohg-ops/myFuse/tree/main/extraFuse


## 實驗
### 安裝FUSE
```
sudo apt-get install fuse libfuse-dev
```

### Mount file system on directory
建立一個mount point 作為file system 操作的directory
```
mkdir mountpoint
```
mount 這個資料夾with fuse
```
./fuse_in_memory_fs mountpoint
```
執行上面指令後fuse_main 會去調用Linux kernel 提供的 mount 系統呼叫，將FUSE file system mount 到指定的目錄。mount後，對 mountpoint 目錄的檔案操作（例如 ls 或 cat）都會被轉發到 FUSE 程式中處理。fuse_in_memory 會一直在背景執行



可以用這個指令查看directory 的系統類型與mount資訊	
```
df -T mountpoint/
```
另外fusermount -u 用來unmount
```
fusermount -u mountpoint
```

## file structure 介紹

- 每個mount point都是一個全新的檔案系統。
- root 是每個mount point最上層
每個檔案都有以下屬性
```
typedef struct file_entry {
    char name[256];              // File or directory name
    char *content;               // File content (NULL for directories)
    size_t size;                 // File size
    int is_directory;            // 1 for directory, 0 for file
    struct timespec atime;       // Access time
    struct timespec mtime;       // Modification time
    struct file_entry *next;     // Pointer to the next sibling
    struct file_entry *child;    // Pointer to the first child (for directories)
} file_entry;
```
假設有下方file system structure
```
/
├── file1
├── dir1
│   ├── file2
│   └── file3
└── file4

```
- file1.next -> dir1
- dir1.next -> file4
- dir1.child -> file2


## File system 的basic function 
- Create, read, and write files
- Open and close files
- Create and remove directories
- List directory contents


#### **Create file 會觸發以下function**
1. do_getattr
- 檢查文件是否已經存在了。
- 會執行`stat("/tmp/mnt/file1")`類似的system call 
- system call會觸發 FUSE 的 do_getattr：
  - 如果 do_getattr 成功（返回 0），表示檔案已存在。
  - 如果 do_getattr 返回 -ENOENT，表示檔案不存在。
2. do_create
創建檔案，設定檔案的屬性
3. do_utimens
- 新文件的時間戳（atime 和 mtime）。
- 檔案建立完後，系統會設定timestamp。

在do_getattr中
- strtok 會按 `/` 分割路徑，例如 /dir1/file1 會被分割為 dir1 和 file1。
- 從root 開始，逐層查找每一級路徑對應的 file_entry。
- 如果某一層級找不到，返回錯誤 -ENOENT（檔案或目錄不存在）。
- while(token)執行完後若檔案存在current 會指向files1
- 並且因為存取過檔案會修改檔案的 `atime` 和 `mtime`

#### **Read file**
會觸發以下函數。
1. do_getattr：
並獲取檔案屬性（如大小）。
2. do_open：
檢查檔案是否存在
3. do_read：
實際執行檔案讀取操作，將內容從檔案載入到緩衝區。

其中程式中的offset 是檔案的起始讀取位置
- 當 offset = 0 時，從檔案的起始位置讀取。
常見於讀取整個檔案內容的情境。
從特定位置開始讀取：
- 當 offset > 0 時，從檔案的某個偏移量開始讀取。
適用於隨機存取（如讀取檔案的中間部分）。
超出檔案末尾的情況：
- 當 offset >= file_entry->size 時，表示嘗試從檔案末尾以外的部分讀取。
這種情況下，應返回 0，表示沒有資料可讀取。

#### **Wrtie file** 
會觸發以下函數。
1. do_open
檢查檔案是否存在
2. do_write
將資料寫入檔案

#### **Remove file**
會觸發以下函數
1. do_getattr
檢查檔案是否存在
2. do_unlink
執行實際的刪除，將父目錄的child link 中移除目標file

#### **Create directories**
會觸發以下函數
1. do_getattr
檢查目錄的父目錄是否存在。
確認父目錄是否是一個合法的目錄。
2. do_mkdir
執行實際的刪除，將父目錄的child link 中移除目標目錄

#### **Close directories**
會觸發以下函數。
1. do_getattr
檢查目錄的父目錄是否存在。
確認父目錄是否是一個合法的目錄。
2. do_rmdir
移除目錄
將新目錄添加到父目錄的子項目鏈表中。

#### List directory contents.
會觸發以下函數
1. do_getattr
檢查目錄是否存在
2. do_readdir
- 用來遍歷檔案
- while(token) 執行完 current 會指向要遍歷的目錄
- current->child 指向該目錄的第一個檔案
- buf 用來存放遍歷到的檔案或目錄名
- 每個目錄至少包含 .（當前目錄）和 ..（上一層目錄）


### Integrating AES-256 Encryption
#### AES-256
- 一種對稱式的加密(加解密使用相同key)
- block cipher:每次加密固定大小的block
Cipher Block Chaining
每個block的加密结果依賴於前一個block的加密结果。
加密需要一個初始化向量（IV）作為第一個block的输入。

#### 加密
為每個檔案準備 
- 256-bit (32-byte) key
- 128-bit (16-byte) IV

假設data 有2個block:block1、block2
若block長度不足 16 char，會利用padding（如 \x06 表示填充 6）補滿16char。

例子
block 1：
plain text:    HelloWorld\x06
XOR(IV):   使用 IV
加密结果:  Block1

block 2：
palin text:    GoodByeWorld\x03
XOR(Block1): 使用前一個 Block1
加密结果:  Block2

整個加密完的data為：[Block1][Blcok2][Block3]...

#### 解密
使用和加密相同的key
剛剛加密完的Ciphertext: [Block1][Block2][Block3]...

解密block 1:
加密结果:  Block1
XOR(IV):   使用 IV
結果:  block1

解密block 2:
加密结果:  Block2
XOR(IV):   使用 Block1 
結果:  block2

- 為了為每個檔案在read/write 時加密，我們在file 的entry 中加入了key 和 iv 這兩個欄位。
- key 和 iv 是 每個檔案或目錄專屬的加密密鑰和初始向量。
- 這些值會在檔案創建時以隨機數 (RAND_bytes) 生成，並儲存在記憶體中。
- 且每個檔案都有自己的唯一密鑰和初始向量，這樣即使檔案內容重複，密文也會不同。

另外file_handle 的key 和iv是每次開啟檔案時會將對應的eky 和iv 複製到file_handle 中，這樣可以避免每次開啟檔案時都要從file_entry中取值。
