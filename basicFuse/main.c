#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// In-memory structure for files and directories
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

file_entry *root; // Root directory

// Initialize the filesystem
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

// Find a file or directory within a given directory
file_entry *find_entry(file_entry *dir, const char *name) {
    file_entry *current = dir->child;
    while (current) {
        if (strcmp(current->name, name) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

// Parse the path and locate the parent directory and entry name
file_entry *get_parent(const char *path, char *name) {
    char *parent_path = strdup(path);
    char *entry_name = strrchr(parent_path, '/');
    if (!entry_name) {
        free(parent_path);
        return NULL;
    }

    if (entry_name == parent_path) {
        // 根目錄下的直接子項
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

// Get file or directory attributes
static int do_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));

    file_entry *current = root;
    char *token = strtok(strdup(path), "/");
    while (token) {
        current = find_entry(current, token);
        if (!current)
            return -ENOENT;
        token = strtok(NULL, "/");
    }

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

// List directory contents
static int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    file_entry *current = root;
    char *token = strtok(strdup(path), "/");
    while (token) {
        current = find_entry(current, token);
        if (!current)
            return -ENOENT;
        token = strtok(NULL, "/");
    }

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

// Create a file
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

    return 0;
}
static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info) {
    // 找到檔案
    file_entry *current = root;
    char *path_copy = strdup(path);  // 複製路徑，避免修改原始字串
    char *token = strtok(path_copy, "/");
    while (token) {
        current = find_entry(current, token);
        if (!current) {
            free(path_copy);
            return -ENOENT; // 檔案不存在
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);

    if (current->is_directory) {
        return -EISDIR; // 無法對目錄進行寫入
    }

    // 動態分配或擴展檔案內容
    if (!current->content) {
        current->content = (char *)malloc(offset + size + 1); // 包含終止符
        if (!current->content) {
            return -ENOMEM; // 記憶體分配失敗
        }
        memset(current->content, 0, offset); // 初始化未寫入的部分為 0
    } else if (offset + size > current->size) {
        char *new_content = (char *)realloc(current->content, offset + size + 1);
        if (!new_content) {
            return -ENOMEM; // 記憶體擴展失敗
        }
        current->content = new_content;
        memset(current->content + current->size, 0, (offset + size) - current->size); // 初始化新分配的部分
    }

    // 寫入資料
    memcpy(current->content + offset, buffer, size);
    current->size = offset + size; // 更新檔案大小
    current->content[current->size] = '\0'; // 確保以空字元結束
    clock_gettime(CLOCK_REALTIME, &current->mtime); // 更新修改時間

    return size; // 返回成功寫入的字節數
}

// Read from a file
static int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    file_entry *current = root;
    char *token = strtok(strdup(path), "/");
    while (token) {
        current = find_entry(current, token);
        if (!current)
            return -ENOENT;
        token = strtok(NULL, "/");
    }

    if (current->is_directory)
        return -EISDIR;

    if (offset >= current->size)
        return 0;

    if (offset + size > current->size)
        size = current->size - offset;

    memcpy(buf, current->content + offset, size);
    clock_gettime(CLOCK_REALTIME, &current->atime);
    return size;
}

// Create a directory
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
    char *token = strtok(strdup(path), "/");
    while (token) {
        current = find_entry(current, token);
        if (!current)
            return -ENOENT;
        token = strtok(NULL, "/");
    }

    if (current->is_directory)
        return -EISDIR;

    return 0;
}


// Update file timestamps
static int do_utimens(const char *path, const struct timespec ts[2]) {
    file_entry *current = root;
    char *token = strtok(strdup(path), "/");
    while (token) {
        current = find_entry(current, token);
        if (!current)
            return -ENOENT;
        token = strtok(NULL, "/");
    }

    current->atime = ts[0];
    current->mtime = ts[1];
    return 0;
}

static int do_release(const char *path, struct fuse_file_info *fi) {
    // 在這個簡單的實作中，無需進行任何操作
    return 0;
}

static int do_rmdir(const char *path) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *prev = NULL;
    file_entry *current = parent->child;

    // 找到要刪除的目錄
    while (current) {
        if (strcmp(current->name, name) == 0) {
            if (!current->is_directory)
                return -ENOTDIR;
            if (current->child != NULL)
                return -ENOTEMPTY;

            // 從鏈表中移除該目錄
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

static int do_unlink(const char *path) {
    char name[256];
    file_entry *parent = get_parent(path, name);
    if (!parent)
        return -ENOENT;

    file_entry *prev = NULL;
    file_entry *current = parent->child;

    // 找到要刪除的檔案
    while (current) {
        if (strcmp(current->name, name) == 0) {
            if (current->is_directory)
                return -EISDIR;

            // 從鏈表中移除該檔案
            if (prev)
                prev->next = current->next;
            else
                parent->child = current->next;

            // 釋放檔案內容和結構
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


// Define FUSE operations
static struct fuse_operations operations = {
    .getattr = do_getattr,
    .readdir = do_readdir,
    .create = do_create,
    .write = do_write,
    .open    = do_open,  
    .read = do_read,
    .mkdir = do_mkdir,
    .utimens = do_utimens,
    .rmdir    = do_rmdir,    
    .release  = do_release,  
    .unlink   = do_unlink, 
    .truncate = do_truncate,

};

int main(int argc, char *argv[]) {
    init_fs();
    return fuse_main(argc, argv, &operations, NULL);
}
