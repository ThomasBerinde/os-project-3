#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#define __DEBUG 10

#ifdef __DEBUG

void debug_message(const char* file, const char* function, const int line)
{
    printf("[PROGRAM] FILE:\"%s\"; FUNCTION:\"%s\"; LINE:\"%d\"; MESSAGE: ", file, function, line);
}

#define LOG(msg) { \
    debug_message(__FILE__, __FUNCTION__, __LINE__);    \
    printf(msg "; strerror: ");   \
    printf("%s\n", strerror(errno));    \
    exit(1);    \
}

#define INFO(msg) {     \
    debug_message(__FILE__, __FUNCTION__, __LINE__);    \
    printf(msg "\n");   \
}

#else

#define LOG(msg) {  \
    printf("[PROGRAM] " msg "\n");   \
    exit(1);    \
}

#define INFO(msg) {     \
    printf("[PROGRAM] " msg "\n");   \
}

#endif

#define BUFFSIZE 256
#define SHM_SIZE 2752347
#define SHM_NAME "/Ix0Qu7"

void wrstat_resp_pipe(int resp_fd, int status) 
{
    if (status == 0) {
        // Write the success message on the response pipe and return from the function
        write(resp_fd, "\x07" "SUCCESS", 8);
    }
    else {
        // Write the error message on the respone pipe
        write(resp_fd, "\x05" "ERROR", 6);      
    }
}

// DONE
void ping(int resp_fd) 
{
    unsigned int nr = 93050;

    write(resp_fd, "\x04" "PING", 5);
    write(resp_fd, "\x04" "PONG", 5);
    write(resp_fd, &nr, sizeof(nr));
}
// DONE
void create_shm(int resp_fd, char** shm_ref) {

    int shm_fd = -1, status = 0;

    // Input validation
    if (shm_ref ==  NULL) {
        LOG("invalid parameter \"shm_ref\"");
    }

    // Create a shared memory object with permissions 664
    shm_fd = shm_open("/Ix0Qu7", O_CREAT | O_RDWR, 0777);
    if (shm_fd < 3) {
        printf("shm_fd is %d\n", shm_fd);
        INFO("failed to create shared memory object");
        status = -1;
        goto cleanup;
    }

    // (Must) set the size of the shared memeory object
    if (ftruncate(shm_fd, SHM_SIZE) != 0) {
        INFO("failed to set size of shared memory object");
        status = -1;
        goto cleanup;
    }

    // Map the entire shared memory object into memory for reading purposes
    *shm_ref = (char*) mmap(0, SHM_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, shm_fd, 0);
    if (*shm_ref == MAP_FAILED) {
        INFO("could not load shared memory object into memory");
        status = -1;
        goto cleanup;
    }

    char buff[] = "abracadabra";
    memcpy(*shm_ref, buff, 4);
    INFO("hello from create_shm after memcpy");
    printf("[PROGRAM] shm_ref is %p\n", *shm_ref);

    // Close the file by using the file descriptor
    // It is now mapped in memory and we have a pointer to it so there is no
    // need to acess it through system calls now
    close(shm_fd);

cleanup:
    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}
// DONE
void write_to_shm(int resp_fd, char* shm_ref, unsigned int offset, unsigned int value) {
    
    int status = 0;
    char* new_shm_ref = NULL;

    // Input validation
    if (shm_ref ==  NULL) {
        LOG("invalid parameter \"shm_ref\"");
    }

    // Check if offset is inside the shared memory 
    if (offset < 0 || offset > SHM_SIZE - sizeof(unsigned int) + 1) {
        INFO("offset is not inside the bounds of the shared memory object");
        status = -1;
        goto cleanup;
    }

    // Copy the value at the specified offset
    new_shm_ref = shm_ref + offset;
    *((unsigned int*) new_shm_ref) = value;

cleanup:
    // Close shared memory
    munmap(shm_ref, SHM_SIZE);
    shm_ref = NULL;

    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}
// DONE
void map_file(int resp_fd, char** file_ref, int *file_size, char* file_name) {

    int file_fd = -1, status = 0;
    struct stat file_matadata;

    // Input validation
    if (file_ref ==  NULL) {
        LOG("invalid parameter \"file_ref\"");
    }
    if (file_size == NULL) {
        LOG("invalid parameter \"file_size\"")
    }
    if (file_name ==  NULL) {
        LOG("invalid parameter \"file_name\"");
    }

    // Open the file to be mapped into memory
    file_fd = open(file_name, O_RDONLY, 0);
    if (file_fd < 3) {
        INFO("opening file failed");
        status = -1;
        goto cleanup;
    }

    // Read file metadata to find its size
    if (0 != stat(file_name, &file_matadata)) {
        INFO("could not read file metadata");
        status = -1;
        goto cleanup;
    }
    *file_size = file_matadata.st_size;

    printf("[PROGRAM] file_size is %d\n", *file_size);

    // Map the file into process' VAS
    *file_ref = (char*) mmap(0, *file_size, PROT_READ, MAP_SHARED, file_fd, 0);
    if (*file_ref == (void*) -1) {
        INFO("could not map file into memory");
        status = -1;
        goto cleanup;
    }

cleanup:
    // Close file 
    if (file_fd > 3) {
        close(file_fd);
    }

    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}
// DONE
void read_from_file_offset(int resp_fd, char* shm_ref, char* file_ref, int file_size, unsigned int offset, unsigned int no_of_bytes) {

    int status = 0;

    // Input validation
    if (shm_ref ==  NULL) {
        LOG("invalid parameter \"shm_ref\"");
    }
    if (file_ref ==  NULL) {
        LOG("invalid parameter \"file_ref\"");
    }

    // Check if offset and bytes to write don't exceed the size of the memory mapped file
    if (offset + no_of_bytes > file_size) {
        INFO("memory to read is not within mapped file boundary");
        status = -1;
        goto cleanup;
    }

    // Copy specified content from currently mapped file and paste into the beginning of the mamory mapped shared memory object
    memcpy(shm_ref, file_ref + offset, no_of_bytes);

cleanup:

    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}

// WAITING
void read_from_file_section(int resp_fd, unsigned int section_no, unsigned int offset, unsigned int no_of_bytes) {
    return;
}

// WAITING
void read_from_logical_space_offset(int resp_fd, unsigned int logical_offset, unsigned int no_of_bytes) {
    return;
}

void loop(int resp_fd, int req_fd) 
{
    int bytes_read = 0, file_size = -1;
    char cmd[BUFFSIZE];
    char* file_ref = NULL, *shm_ref = NULL;
    unsigned char cmd_size = '\0';

    while(1) 
    {
        bytes_read = read(req_fd, &cmd_size, 1);
        if (bytes_read != 1) {
            LOG("cmd_size read incorrectly");
        }

        bytes_read = read(req_fd, cmd, cmd_size);
        if(bytes_read != cmd_size) {
            LOG("cmd read incorrectly");
        }

        cmd[bytes_read] = '\0';
        // setbuf(stdout, NULL);

        printf("[PROGRAM] received string \'%s\'\n", cmd);
        
    // PING
        if (strcmp(cmd, "PING") == 0) {
            ping(resp_fd);
        } 
    // EXIT
        else if (strcmp(cmd, "EXIT") == 0) {
            // Implement EXIT
            break;
        }
    // CREATE SHARED MEMORY
        else if (strcmp(cmd, "CREATE_SHM") == 0) {
            unsigned int shm_size = 0;

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x0A" "CREATE_SHM", 11);

            bytes_read = read(req_fd, &shm_size, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("shm_size read incorrectly");
            }

            create_shm(resp_fd, &shm_ref);
        }
    // WRITE TO SHARED MEMORY
        else if (strcmp(cmd, "WRITE_TO_SHM") == 0) {
            unsigned int offset= 0, value = 0;

            // Wite the appropriate message on the response pipe
             write(resp_fd, "\x0C" "WRITE_TO_SHM", 13);

            bytes_read = read(req_fd, &offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("offset read incorrectly");
            }

            bytes_read = read(req_fd, &value, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("value read incorrectly");
            }

            printf("offset=%u value=%u\n", offset, value);

            write_to_shm(resp_fd, shm_ref, offset, value);
        }
    // MAP FILE
        else if (strcmp(cmd, "MAP_FILE") == 0) {
            char file_name[BUFFSIZE];
            unsigned char size = '\0';

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x08" "MAP_FILE", 9);

            bytes_read = read(req_fd, &size, 1);
            if (bytes_read != 1) {
                LOG("file name size read incorrectly");
            }

            bytes_read = read(req_fd, file_name, size);
            if (bytes_read != size) {
                LOG("file name read incorrectly");
            }

            file_name[bytes_read] = '\0';
            
            map_file(resp_fd, &file_ref, &file_size, file_name);
        }
    // READ FROM FILE OFFSET
        else if (strcmp(cmd, "READ_FROM_FILE_OFFSET") == 0) {
            unsigned int offset = 0, no_of_bytes = 0;

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x15" "READ_FROM_FILE_OFFSET", 22);

            bytes_read = read(req_fd, &offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("offset read incorrectly");
            }

            bytes_read = read(req_fd, &no_of_bytes, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("nr_of_bytes read incorrectly");
            }

            read_from_file_offset(resp_fd, shm_ref, file_ref, file_size, offset, no_of_bytes);

            // // Close shared memory
            // munmap(shm_ref, SHM_SIZE);
            // shm_ref = NULL;
        }
    // READ FROM FILE SECTION
        else if (strcmp(cmd, "READ_FROM_FILE_SECTION") == 0) {
            unsigned int section_no = 0, offset = 0, no_of_bytes = 0;

            bytes_read = read(req_fd, &section_no, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("section_no read incorrectly");
            }

            bytes_read = read(req_fd, &offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("offset read incorrectly");
            }

            bytes_read = read(req_fd, &no_of_bytes, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("nr_of_bytes read incorrectly");
            }

            read_from_file_section(resp_fd, section_no, offset, no_of_bytes);
        }
    // READ FROM LOGICAL SPACE OFFSET
        else if (strcmp(cmd, "READ_FROM_LOGICAL_SPACE_OFFSET") == 0) {
            unsigned int logical_offset = 0, no_of_bytes = 0;

            bytes_read = read(req_fd, &logical_offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("section_no read incorrectly");
            }

            bytes_read = read(req_fd, &no_of_bytes, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("section_no read incorrectly");
            }

            read_from_logical_space_offset(resp_fd, logical_offset, no_of_bytes);
        }
    }
}

void connect(int* resp_fd, int* req_fd) 
{
    // Create a response pipse with permissions for writing
    mkfifo("RESP_PIPE_93050", 0666);

    // Open the request pipe, created by the tester, for reading
    *req_fd = open("REQ_PIPE_93050", O_RDWR);
    if (*req_fd < 3) {
        LOG("ERROR\ncannot open the request pipe");
    }

    // Opens the response pipe for writing
    *resp_fd = open("RESP_PIPE_93050", O_RDWR);
    if (*resp_fd < 3) {
        LOG("ERROR\ncannot create the response pipe");
    }

    // Write "CONNECT" on the response pipe
    write(*resp_fd, "\x07" "CONNECT", 8);

    printf("SUCCESS\n");
}

int main() 
{
    /*
    mkfifo("testpipe", 0666);
    tail -f
    echo "Whatevs" > testpipe 
    */

    int resp_fd = -1, req_fd = -1;

    connect(&resp_fd, &req_fd);

    loop(resp_fd, req_fd);

    return 0;
}