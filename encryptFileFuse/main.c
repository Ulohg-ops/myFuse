#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>

// 初始化 OpenSSL
void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// 清理 OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

// 將單一十六進位字元(0-9, A-F, a-f)轉為 0x0 ~ 0xF
static int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1; // 非 hex 字元就回傳 -1
}

/**
 * 將 hex_str 轉成二進位 byte 存入 out，最多 parse_len 個 byte。
 * 如果 hex_str 長度不足 parse_len*2，就用 0x00 填補。
 * 回傳成功轉換的 byte 數。
 */
static size_t hex_str_to_bin(const char *hex_str, unsigned char *out, size_t parse_len)
{
    // parse_len = 預期要轉換的 byte 數 (對金鑰來說是 32)
    // hex_str 可能含有 0~64(或更多) 個 hex 字元，本函式只處理最前面的 2*parse_len 字元
    size_t hex_len = strlen(hex_str);
    // 最多只看 2*parse_len (64) 字元
    if (hex_len > parse_len * 2) {
        hex_len = parse_len * 2;
    }

    // 逐一轉換
    size_t i = 0; // i 會跑在 hex_str 上
    size_t out_idx = 0; 
    while (i < hex_len) {
        // 取兩個 hex 字元, 若只有一個字元剩就補 0
        int high_val = hex_char_to_val(hex_str[i]);
        if (high_val < 0) {
            // 遇到非法 hex 字元，可視需求處理
            high_val = 0;
        }

        int low_val = 0;
        if (i + 1 < hex_len) {
            low_val = hex_char_to_val(hex_str[i + 1]);
            if (low_val < 0) {
                low_val = 0;
            }
        }

        out[out_idx++] = (unsigned char)((high_val << 4) | low_val);

        i += 2;
        if (out_idx >= parse_len) break; 
    }

    // 如果不足 parse_len 個 byte，就用 0x00 補齊
    while (out_idx < parse_len) {
        out[out_idx++] = 0x00;
    }
    return out_idx;
}


// 加密函數
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        return -1;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// 解密函數
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        return -1;
    plaintext_len = len;

    // 若解密失敗，表示金鑰錯誤或內容被破壞，回傳-1
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

typedef struct file_handle {
    struct file_entry *entry;
    unsigned char key[32]; // 256位元的金鑰，由使用者輸入
    unsigned char iv[16];  // 128位元的初始向量，從檔案結構取得
} file_handle;

typedef struct file_entry {
    char name[256];              
    char *content;               
    size_t size;                 
    int is_directory;            
    struct timespec atime;       
    struct timespec mtime;       
    struct file_entry *next;     
    struct file_entry *child;    
    unsigned char key[32];       // 每個檔案有自己獨立的金鑰 (在 create 時隨機產生)
    unsigned char iv[16];        // 每個檔案有自己的 IV
    int has_key;                 
} file_entry;

file_entry *root; // 根目錄

// 初始化檔案系統
void init_fs() {
    root = (file_entry *)malloc(sizeof(file_entry));
    strcpy(root->name, "/");
    root->is_directory = 1;
    root->content = NULL;
    root->size = 0;
    clock_gettime(CLOCK_REALTIME, &root->atime);
    clock_gettime(CLOCK_REALTIME, &root->mtime);
    root->next = NULL;
    root->child = NULL;
    root->has_key = 0;
}

file_entry *find_entry(file_entry *dir, const char *name) {
    file_entry *current = dir->child;
    while (current) {
        if (strcmp(current->name, name) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

file_entry *get_parent(const char *path, char *name) {
    char *parent_path = strdup(path);
    char *entry_name = strrchr(parent_path, '/');
    if (!entry_name) {
        free(parent_path);
        return NULL;
    }

    if (entry_name == parent_path) {
        strcpy(name, entry_name + 1);
        free(parent_path);
        return root;
    }

    *entry_name = '\0';
    entry_name++;
    strcpy(name, entry_name);

    file_entry *current = root;
    char *token = strtok(parent_path, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current || !current->is_directory) {
            free(parent_path);
            return NULL;
        }
        token = strtok(NULL, "/");
    }
    free(parent_path);
    return current;
}

static int do_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));

    file_entry *current = root;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current) {
            free(path_copy);
            return -ENOENT;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);

    if (current->is_directory) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = current->size;
    }
    stbuf->st_atim = current->atime;
    stbuf->st_mtim = current->mtime;

    return 0;
}

static int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    file_entry *current = root;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current) {
            free(path_copy);
            return -ENOENT;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);

    if (!current->is_directory)
        return -ENOTDIR;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    file_entry *child = current->child;
    while (child) {
        filler(buf, child->name, NULL, 0);
        child = child->next;
    }

    return 0;
}

static int do_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *new_file = (file_entry *)malloc(sizeof(file_entry));
    strcpy(new_file->name, name);
    new_file->is_directory = 0;
    new_file->content = NULL;
    new_file->size = 0;
    clock_gettime(CLOCK_REALTIME, &new_file->atime);
    clock_gettime(CLOCK_REALTIME, &new_file->mtime);
    new_file->next = parent->child;
    new_file->child = NULL;
    parent->child = new_file;

    // 產生金鑰與 IV
    if (!RAND_bytes(new_file->key, sizeof(new_file->key)))
        return -EIO;
    if (!RAND_bytes(new_file->iv, sizeof(new_file->iv)))
        return -EIO;
    new_file->has_key = 1;

    // ---------------  在此處印出金鑰和 IV  ---------------
    fprintf(stderr, "[CREATE] Key for file '%s': ", path);
    for (int i = 0; i < 32; i++) {
        fprintf(stderr, "%02X", new_file->key[i]);
    }
    fprintf(stderr, "\n");

    // fprintf(stderr, "[CREATE] IV for file '%s': ", path);
    // for (int i = 0; i < 16; i++) {
    //     fprintf(stderr, "%02X", new_file->iv[i]);
    // }
    // fprintf(stderr, "\n");
    // // ----------------------------------------------------

    return 0;
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info) {
    file_handle *fh = (file_handle *)info->fh;
    file_entry *current = fh->entry;

    if (current->is_directory)
        return -EISDIR;

    int max_ciphertext_len = size + EVP_MAX_BLOCK_LENGTH;
    unsigned char *ciphertext = malloc(max_ciphertext_len);
    if (!ciphertext)
        return -ENOMEM;

    int ciphertext_len = encrypt((unsigned char *)buffer, size, fh->key, fh->iv, ciphertext);
    if (ciphertext_len < 0) {
        free(ciphertext);
        return -EIO;
    }

    if (!current->content) {
        current->content = (char *)malloc(ciphertext_len);
        if (!current->content) {
            free(ciphertext);
            return -ENOMEM;
        }
        memcpy(current->content, ciphertext, ciphertext_len);
        current->size = ciphertext_len;
    } else {
        current->content = realloc(current->content, ciphertext_len);
        if (!current->content) {
            free(ciphertext);
            return -ENOMEM;
        }
        memcpy(current->content, ciphertext, ciphertext_len);
        current->size = ciphertext_len;
    }

    clock_gettime(CLOCK_REALTIME, &current->mtime);
    free(ciphertext);

    return size;
}

static int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    file_handle *fh = (file_handle *)fi->fh;
    file_entry *current = fh->entry;

    if (current->is_directory)
        return -EISDIR;

    if (!current->content)
        return 0;

    unsigned char *plaintext = malloc(current->size + 1);
    if (!plaintext)
        return -ENOMEM;

    int plaintext_len = decrypt((unsigned char *)current->content, current->size, fh->key, fh->iv, plaintext);
    if (plaintext_len < 0) {
        free(plaintext);
        // 解密失敗表示金鑰錯誤或內容遭破壞
        return -EIO;
    }

    if (offset >= (off_t)plaintext_len) {
        free(plaintext);
        return 0;
    }

    if (offset + size > (size_t)plaintext_len)
        size = plaintext_len - offset;

    memcpy(buf, plaintext + offset, size);
    free(plaintext);

    clock_gettime(CLOCK_REALTIME, &current->atime);
    return size;
}

static int do_mkdir(const char *path, mode_t mode) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *new_dir = (file_entry *)malloc(sizeof(file_entry));
    strcpy(new_dir->name, name);
    new_dir->is_directory = 1;
    clock_gettime(CLOCK_REALTIME, &new_dir->atime);
    clock_gettime(CLOCK_REALTIME, &new_dir->mtime);
    new_dir->next = parent->child;
    new_dir->child = NULL;
    parent->child = new_dir;

    return 0;
}

// 開啟檔案時要求使用者提供金鑰
static int do_open(const char *path, struct fuse_file_info *fi) {
    file_entry *current = root;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current) {
            free(path_copy);
            return -ENOENT;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);

    if (current->is_directory)
        return -EISDIR;

    // 分配 file_handle
    file_handle *fh = malloc(sizeof(file_handle));
    if (!fh)
        return -ENOMEM;
    fh->entry = current;

    fprintf(stderr, 
        "請輸入檔案 '%s' 的 32 Byte 金鑰（以十六進位表示，最多 64 字元，不足自動補 0x00）：\n",
        current->name
    );
    fflush(stderr);

    // 取得使用者輸入的 hex 字串
    char hex_input[256];
    memset(hex_input, 0, sizeof(hex_input));
    if (fgets(hex_input, sizeof(hex_input), stdin) != NULL) {
        // 移除換行符號
        char *newline = strchr(hex_input, '\n');
        if (newline) *newline = '\0';
    }

    // 將 hex 字串轉為 32 bytes 二進位
    unsigned char user_key[32];
    hex_str_to_bin(hex_input, user_key, 32);

    // 與檔案 key 做比對
    if (memcmp(user_key, current->key, 32) != 0) {
        fprintf(stderr, "[ERROR] 金鑰不正確，開啟檔案失敗。\n");
        free(fh);
        return -EACCES;  // 開檔失敗
    }

    // 若金鑰符合，才把 key/iv 存入 fh 用於後續加解密
    memcpy(fh->key, user_key, sizeof(fh->key));
    memcpy(fh->iv, current->iv, sizeof(current->iv));

    fi->fh = (uint64_t)fh;
    return 0;
}

static int do_release(const char *path, struct fuse_file_info *fi) {
    file_handle *fh = (file_handle *)fi->fh;
    if (fh)
        free(fh);
    return 0;
}

static int do_utimens(const char *path, const struct timespec ts[2]) {
    file_entry *current = root;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current) {
            free(path_copy);
            return -ENOENT;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);

    current->atime = ts[0];
    current->mtime = ts[1];
    return 0;
}

static int do_truncate(const char *path, off_t size) {
    file_entry *current = root;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current) {
            free(path_copy);
            return -ENOENT;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);

    if (current->is_directory)
        return -EISDIR;

    if (size == 0) {
        free(current->content);
        current->content = NULL;
    } else {
        char *new_content = realloc(current->content, size);
        if (!new_content)
            return -ENOMEM;
        if ((size_t)size > current->size)
            memset(new_content + current->size, 0, size - current->size);
        current->content = new_content;
    }
    current->size = size;
    clock_gettime(CLOCK_REALTIME, &current->mtime);

    return 0;
}

static int do_rmdir(const char *path) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *prev = NULL;
    file_entry *current = parent->child;

    while (current) {
        if (strcmp(current->name, name) == 0) {
            if (!current->is_directory)
                return -ENOTDIR;
            if (current->child != NULL)
                return -ENOTEMPTY;

            if (prev)
                prev->next = current->next;
            else
                parent->child = current->next;

            free(current);
            return 0;
        }
        prev = current;
        current = current->next;
    }
    return -ENOENT;
}

static int do_unlink(const char *path) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *prev = NULL;
    file_entry *current = parent->child;

    while (current) {
        if (strcmp(current->name, name) == 0) {
            if (current->is_directory)
                return -EISDIR;

            if (prev)
                prev->next = current->next;
            else
                parent->child = current->next;

            if (current->content)
                free(current->content);
            free(current);

            return 0;
        }
        prev = current;
        current = current->next;
    }
    return -ENOENT;
}

static struct fuse_operations operations = {
    .getattr  = do_getattr,
    .readdir  = do_readdir,
    .create   = do_create,
    .write    = do_write,
    .open     = do_open,
    .read     = do_read,
    .mkdir    = do_mkdir,
    .unlink   = do_unlink,
    .rmdir    = do_rmdir,
    .release  = do_release,
    .utimens  = do_utimens,
    .truncate = do_truncate,
};

int main(int argc, char *argv[]) {
    init_openssl();
    init_fs();
    int ret = fuse_main(argc, argv, &operations, NULL);
    cleanup_openssl();
    return ret;
}
