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

// -------------------------
// 您的 AES-256 CBC encrypt()/decrypt()
// -------------------------
int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// -------------------------
// 其他結構 & 函式
// -------------------------
void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}
void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

typedef struct file_entry {
    char name[256];
    unsigned char *content;   // 加密後內容
    size_t size;              // 密文大小
    int is_directory;
    struct timespec atime;
    struct timespec mtime;
    struct file_entry *next;
    struct file_entry *child;

    unsigned char key[32];
    unsigned char iv[16];
    int has_key;
} file_entry;

file_entry *root;

typedef struct file_handle {
    struct file_entry *entry;
    unsigned char key[32];
    unsigned char iv[16];
} file_handle;

void init_fs() {
    root = (file_entry *)malloc(sizeof(file_entry));
    memset(root, 0, sizeof(file_entry));
    strcpy(root->name, "/");
    root->is_directory = 1;
    clock_gettime(CLOCK_REALTIME, &root->atime);
    clock_gettime(CLOCK_REALTIME, &root->mtime);
}

// 幫助函式：找父目錄
file_entry *find_entry(file_entry *dir, const char *name) {
    file_entry *cur = dir->child;
    while (cur) {
        if (strcmp(cur->name, name) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}
file_entry *get_parent(const char *path, char *name) {
    char *ppath = strdup(path);
    char *entry_name = strrchr(ppath, '/');
    if (!entry_name) {
        free(ppath);
        return NULL;
    }
    if (entry_name == ppath) {
        strcpy(name, entry_name + 1);
        free(ppath);
        return root;
    }

    *entry_name = '\0';
    entry_name++;
    strcpy(name, entry_name);

    file_entry *current = root;
    char *token = strtok(ppath, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current || !current->is_directory) {
            free(ppath);
            return NULL;
        }
        token = strtok(NULL, "/");
    }
    free(ppath);
    return current;
}

// -------------------------
// 這個函式把 \n 顯示為 \n
// -------------------------
static void print_escaped_string(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (c == '\n') {
            printf("\\n");
        } else {
            putchar(c);
        }
    }
}

// -------------------------
// FUSE callbacks
// -------------------------
static int do_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));

    file_entry *current = root;
    char *copy = strdup(path);
    char *tok = strtok(copy, "/");
    while(tok) {
        current = find_entry(current, tok);
        if (!current) {
            free(copy);
            return -ENOENT;
        }
        tok = strtok(NULL, "/");
    }
    free(copy);

    if (current->is_directory) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = current->size; // 回傳「密文大小」
    }
    stbuf->st_atim = current->atime;
    stbuf->st_mtim = current->mtime;
    return 0;
}

static int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    file_entry *current = root;
    char *copy = strdup(path);
    char *tok = strtok(copy, "/");
    while(tok) {
        current = find_entry(current, tok);
        if (!current) {
            free(copy);
            return -ENOENT;
        }
        tok = strtok(NULL, "/");
    }
    free(copy);

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

    file_entry *f = (file_entry *)malloc(sizeof(file_entry));
    memset(f, 0, sizeof(file_entry));
    strcpy(f->name, name);
    f->is_directory = 0;
    clock_gettime(CLOCK_REALTIME, &f->atime);
    clock_gettime(CLOCK_REALTIME, &f->mtime);

    // random key & iv
    RAND_bytes(f->key, sizeof(f->key));
    RAND_bytes(f->iv, sizeof(f->iv));
    f->has_key = 1;

    f->next = parent->child;
    parent->child = f;

    return 0;
}

static int do_open(const char *path, struct fuse_file_info *fi) {
    file_entry *current = root;
    char *copy = strdup(path);
    char *tok = strtok(copy, "/");
    while(tok) {
        current = find_entry(current, tok);
        if (!current) {
            free(copy);
            return -ENOENT;
        }
        tok = strtok(NULL, "/");
    }
    free(copy);

    if (current->is_directory)
        return -EISDIR;

    file_handle *fh = (file_handle *)malloc(sizeof(file_handle));
    fh->entry = current;
    memcpy(fh->key, current->key, 32);
    memcpy(fh->iv, current->iv, 16);

    fi->fh = (uint64_t)fh;
    return 0;
}

// -----------
// do_write
// -----------
static int do_write(const char *path, const char *buffer, size_t size,
                    off_t offset, struct fuse_file_info *fi)
{
    file_handle *fh = (file_handle *)fi->fh;
    file_entry *current = fh->entry;

    if (current->is_directory)
        return -EISDIR;

    // 解密舊內容
    unsigned char *old_plaintext = NULL;
    int old_plaintext_len = 0;
    if (current->content && current->size > 0) {
        old_plaintext = (unsigned char*)malloc(current->size + 1);
        memset(old_plaintext, 0, current->size + 1);
        old_plaintext_len = decrypt(current->content, current->size, fh->key, fh->iv, old_plaintext);
        if (old_plaintext_len < 0) {
            free(old_plaintext);
            return -EIO;
        }
    } else {
        old_plaintext_len = 0;
        old_plaintext = (unsigned char*)calloc(1,1);
    }

    int new_len = (offset + size > (size_t)old_plaintext_len) ? offset + size : old_plaintext_len;
    unsigned char *new_plaintext = (unsigned char*)malloc(new_len);
    memset(new_plaintext, 0, new_len);

    memcpy(new_plaintext, old_plaintext, old_plaintext_len);
    free(old_plaintext);

    memcpy(new_plaintext + offset, buffer, size);

    // 印出「最終明文」（轉義 \n）
    printf("----- do_write -----\n");
    printf("[Write] Final Plaintext: \"");
    print_escaped_string(new_plaintext, new_len);
    printf("\"\n");

    unsigned char *ciphertext = (unsigned char*)malloc(new_len + 16);
    memset(ciphertext, 0, new_len+16);

    int cipher_len = encrypt(new_plaintext, new_len, fh->key, fh->iv, ciphertext);
    if (cipher_len < 0) {
        free(new_plaintext);
        free(ciphertext);
        return -EIO;
    }

    printf("[Write] Ciphertext (hex): ");
    for(int i=0; i < cipher_len; i++){
        printf("%02X", ciphertext[i]);
    }
    printf("\n\n");

    free(new_plaintext);

    if (current->content)
        free(current->content);
    current->content = ciphertext;
    current->size = cipher_len;

    clock_gettime(CLOCK_REALTIME, &current->mtime);
    return size;
}

// -----------
// do_read
// -----------
static int do_read(const char *path, char *buf,
                   size_t size, off_t offset, struct fuse_file_info *fi)
{
    file_handle *fh = (file_handle *)fi->fh;
    file_entry *current = fh->entry;

    if (current->is_directory)
        return -EISDIR;

    if (!current->content || current->size == 0) {
        return 0; 
    }

    // 印出原本的 ciphertext
    printf("----- do_read -----\n");
    printf("[Read] Original Ciphertext (hex): ");
    for (int i = 0; i < (int)current->size; i++) {
        printf("%02X", current->content[i]);
    }
    printf("\n");

    unsigned char *plaintext = (unsigned char*)malloc(current->size + 16);
    memset(plaintext, 0, current->size+16);

    int plaintext_len = decrypt(current->content, current->size, fh->key, fh->iv, plaintext);
    if (plaintext_len < 0) {
        free(plaintext);
        return -EIO;
    }

    // 印出解密後明文
    printf("[Read] Decrypted Plaintext: \"");
    print_escaped_string(plaintext, plaintext_len);
    printf("\"\n\n");

    if ((off_t)plaintext_len <= offset) {
        free(plaintext);
        return 0;
    }
    if (offset + size > (size_t)plaintext_len) {
        size = plaintext_len - offset;
    }

    memcpy(buf, plaintext + offset, size);
    free(plaintext);

    clock_gettime(CLOCK_REALTIME, &current->atime);
    return size;
}

// mkdir
static int do_mkdir(const char *path, mode_t mode) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *dir = (file_entry*)malloc(sizeof(file_entry));
    memset(dir, 0, sizeof(file_entry));
    strcpy(dir->name, name);
    dir->is_directory = 1;
    clock_gettime(CLOCK_REALTIME, &dir->atime);
    clock_gettime(CLOCK_REALTIME, &dir->mtime);
    dir->next = parent->child;
    parent->child = dir;

    return 0;
}

// unlink
static int do_unlink(const char *path) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent) return -ENOENT;

    file_entry *prev = NULL;
    file_entry *cur = parent->child;
    while(cur) {
        if(strcmp(cur->name, name)==0) {
            if (cur->is_directory)
                return -EISDIR;
            if (cur->content)
                free(cur->content);
            if (prev) prev->next = cur->next;
            else parent->child = cur->next;
            free(cur);
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }
    return -ENOENT;
}

// rmdir
static int do_rmdir(const char *path) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent) return -ENOENT;

    file_entry *prev = NULL;
    file_entry *cur = parent->child;
    while(cur) {
        if(strcmp(cur->name, name)==0) {
            if(!cur->is_directory)
                return -ENOTDIR;
            if(cur->child)
                return -ENOTEMPTY;
            if(prev) prev->next = cur->next;
            else parent->child = cur->next;
            free(cur);
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }
    return -ENOENT;
}

// release
static int do_release(const char *path, struct fuse_file_info *fi) {
    file_handle *fh = (file_handle *)fi->fh;
    if(fh) free(fh);
    return 0;
}

// utimens
static int do_utimens(const char *path, const struct timespec ts[2]) {
    file_entry *current = root;
    char *copy = strdup(path);
    char *tok = strtok(copy, "/");
    while(tok) {
        current = find_entry(current, tok);
        if(!current) {
            free(copy);
            return -ENOENT;
        }
        tok = strtok(NULL, "/");
    }
    free(copy);

    current->atime = ts[0];
    current->mtime = ts[1];
    return 0;
}

// truncate (簡化對密文)
static int do_truncate(const char *path, off_t size) {
    file_entry *current = root;
    char *copy = strdup(path);
    char *tok = strtok(copy, "/");
    while(tok) {
        current = find_entry(current, tok);
        if(!current) {
            free(copy);
            return -ENOENT;
        }
        tok = strtok(NULL, "/");
    }
    free(copy);

    if(current->is_directory)
        return -EISDIR;

    if((size_t)size > current->size) {
        unsigned char *new_c = realloc(current->content, size);
        if(!new_c && size>0) return -ENOMEM;
        if(new_c) {
            memset(new_c+current->size, 0, size - current->size);
            current->content = new_c;
        }
        current->size = size;
    } else {
        unsigned char *new_c = realloc(current->content, size);
        if(!new_c && size>0) return -ENOMEM;
        current->content = new_c;
        current->size = size;
    }
    clock_gettime(CLOCK_REALTIME, &current->mtime);
    return 0;
}

static struct fuse_operations operations = {
    .getattr  = do_getattr,
    .readdir  = do_readdir,
    .create   = do_create,
    .open     = do_open,
    .write    = do_write,
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

    printf("=== FUSE In-memory AES-256 Demo ===\n");
    printf("Write/Read will show encrypted & decrypted strings.\n\n");

    return fuse_main(argc, argv, &operations, NULL);
}
