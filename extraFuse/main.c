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

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1)
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
    unsigned char key[32]; // 從 user_key.txt 載入
    unsigned char iv[16];  // 從 keys.txt 載入
    int key_correct;       // 若金鑰正確則為1，否則為0
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

void write_key_to_file(const char *filename, const unsigned char *key, const unsigned char *iv) {
    FILE *key_file = fopen("/home/ulohg/Desktop/myFuse/extraFuse/keys.txt", "a"); // Append mode
    if (!key_file) {
        fprintf(stderr, "Failed to open keys file for writing\n");
        return;
    }

    fprintf(key_file, "File: %s\nKey: ", filename);
    for (int i = 0; i < 32; i++) {
        fprintf(key_file, "%02x", key[i]);
    }
    fprintf(key_file, "\nIV: ");
    for (int i = 0; i < 16; i++) {
        fprintf(key_file, "%02x", iv[i]);
    }
    fprintf(key_file, "\n\n");

    fclose(key_file);
}

int read_key_from_file(const char *filename, unsigned char *key, unsigned char *iv) {
    FILE *key_file = fopen("/home/ulohg/Desktop/myFuse/extraFuse/keys.txt", "r");
    if (!key_file) {
        return -1;
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), key_file)) {
        char file_label[256];
        if (sscanf(line, "File: %s", file_label) == 1) {
            if (strcmp(file_label, filename) == 0) {
                // 找到該檔案的紀錄
                found = 1;
                // 讀取下一行為Key
                if (!fgets(line, sizeof(line), key_file)) break;
                // Key line format: "Key: <64 hex chars>"
                char key_str[65];
                if (sscanf(line, "Key: %64s", key_str) == 1) {
                    for (int i = 0; i < 32; i++) {
                        sscanf(&key_str[i * 2], "%2hhx", &key[i]);
                    }
                } else {
                    found = 0;
                    break;
                }

                // 讀取下一行為IV
                if (!fgets(line, sizeof(line), key_file)) {
                    found = 0;
                    break;
                }
                // IV line format: "IV: <32 hex chars>"
                char iv_str[33];
                if (sscanf(line, "IV: %32s", iv_str) == 1) {
                    for (int i = 0; i < 16; i++) {
                        sscanf(&iv_str[i * 2], "%2hhx", &iv[i]);
                    }
                } else {
                    found = 0;
                }
                break;
            }
        }
    }

    fclose(key_file);
    return found ? 0 : -1;
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

    // Generate a unique key and IV for the file
    unsigned char key[32];
    unsigned char iv[16];
    if (!RAND_bytes(key, sizeof(key)))
        return -EIO;
    if (!RAND_bytes(iv, sizeof(iv)))
        return -EIO;

    // Write the key and IV to the keys file
    write_key_to_file(path, key, iv);

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

    if (fh->key_correct == 1) {
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
    } else {
        // 金鑰錯誤時顯示原始密文
        if (offset >= (off_t)current->size) {
            return 0;
        }
        if (offset + size > current->size)
            size = current->size - offset;

        memcpy(buf, current->content + offset, size);
    }

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

    // 從 keys.txt 中讀取該檔案的金鑰與 IV
    unsigned char stored_key[32];
    unsigned char stored_iv[16];
    if (read_key_from_file(path, stored_key, stored_iv) != 0) {
        fprintf(stderr, "找不到該檔案的金鑰紀錄！\n");
        return -EACCES;
    }

    // 從 user_key.txt 檔案中讀取使用者金鑰
    FILE *key_input_file = fopen("/home/ulohg/Desktop/myFuse/extraFuse/user_key.txt", "r");
    unsigned char user_key[32] = {0};
    char input_key[256];
    int key_correct_flag = 0; // 預設為0，除非成功比對

    if (!key_input_file) {
        fprintf(stderr, "無法開啟 user_key.txt 檔案\n");
        // 無法開啟表示無法取得正確金鑰，此時 key_correct_flag = 0 顯示亂碼
    } else {
        if (fgets(input_key, sizeof(input_key), key_input_file) != NULL) {
            char *newline = strchr(input_key, '\n');
            if (newline) *newline = '\0';

            size_t len = strlen(input_key);
            if (len == 64) {
                for (int i = 0; i < 32; i++) {
                    sscanf(&input_key[i * 2], "%2hhx", &user_key[i]);
                }
                // 比對 user_key 和 stored_key
                if (memcmp(user_key, stored_key, sizeof(stored_key)) == 0) {
                    key_correct_flag = 1;
                } else {
                    fprintf(stderr, "使用者金鑰與儲存的金鑰不匹配，將顯示亂碼。\n");
                }
            } else {
                fprintf(stderr, "金鑰長度錯誤！需要64個十六進位字符。\n");
            }
        } else {
            fprintf(stderr, "無法從 user_key.txt 讀取金鑰\n");
        }
        fclose(key_input_file);
    }

    file_handle *fh = malloc(sizeof(file_handle));
    fh->entry = current;
    memcpy(fh->key, user_key, 32);  
    memcpy(fh->iv, stored_iv, 16);
    fh->key_correct = key_correct_flag;

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
