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

// #define __DEBUG 10

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

#define RESP_PIPE "RESP_PIPE_93050"
#define REQ_PIPE "REQ_PIPE_93050"
#define BUFFSIZE 256
#define SHM_SIZE 2752347
#define SHM_NAME "/Ix0Qu7"
#define PAGE_SIZE 5120

// Structure that holds a section's offset and size
typedef struct {
    unsigned int offset;
    unsigned int size;
} SECT_DATA;

/**
 * @brief Writes a response status on the response pipe
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param status - 0 means "SUCCESS" and anything else is "ERROR"
 */
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

/**
 * @brief Writes response for "PING" command on the response pipe 
 * 
 * @param resp_fd - file descriptor of the response pipe
 */
void ping(int resp_fd) 
{
    unsigned int nr = 93050;

    write(resp_fd, "\x04" "PING", 5);
    write(resp_fd, "\x04" "PONG", 5);
    write(resp_fd, &nr, sizeof(nr));
}

/**
 * @brief Create a shared memory object and mapps it into memory
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param shm_ref - output parameter that will store a reference to the shared memory object mapped into memory
 */
void create_shm(int resp_fd, char** shm_ref) {

    int shm_fd = -1, status = 0;

    // Input validation
    if (shm_ref ==  NULL) {
        LOG("invalid parameter \"shm_ref\"");
    }

    // Create a shared memory object with permissions 664
    shm_fd = shm_open("/Ix0Qu7", O_CREAT | O_RDWR, 0664);
    if (shm_fd < 3) {
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

    // Close the file by using the file descriptor
    // It is now mapped in memory and we have a pointer to it so there is no need to acess it through system calls now
    close(shm_fd);

cleanup:
    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}

/**
 * @brief Writes a value at a specific offset in a shared memory region mapped into memory
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param shm_ref - reference to the shared memroy object mapped into memory
 * @param offset - offset inside the shared memory region
 * @param value - value to be written inside the shared memory region
 */
void write_to_shm(int resp_fd, char* shm_ref, unsigned int offset, unsigned int value) {
    
    int status = 0;


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
    *((unsigned int*) (shm_ref + offset)) = value;

cleanup:

    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}

/**
 * @brief Mapps a file into memory 
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param file_ref - output parameter that will be a reference to the file mapped into memory
 * @param file_size - size of the file to be mapped into memory
 * @param file_name - name of the file to be mapped into memory
 */
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
        INFO("failed to open file");
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

/**
 * @brief Reads a specified number of bytes from an offset inside a file mapped into memroy and writes them into the beginning of a shared memory region mapped into memory
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param shm_ref - reference to the shared memory region mapped into mmemory
 * @param file_ref - reference to the file mapped into memory
 * @param file_size - size of the file mapped into memory 
 * @param offset - offset inside the file mapped into memory
 * @param no_of_bytes - number of bytes to be read from the file and written into the shared memory region
 */
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

/**
 * @brief Reads a specified number of bytes from an offset of a section of the SF file mapped into memory and writes them into the beginning of a shared memory region mapped into memory
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param shm_ref - reference to the shared memory region mapped into mmemory
 * @param file_ref - reference to the SF file mapped into memory
 * @param file_size - size of the SF file mapped into memory 
 * @param section_no - number of the section inside the SF file from which to read (1-indexed)
 * @param offset - offset inside the section of the SF file from which to read
 * @param no_of_bytes - number of bytes to be read from the SF file and written into the shared memory region
 */
void read_from_file_section(int resp_fd, char* shm_ref, char* file_ref, int file_size, unsigned int section_no, unsigned int offset, unsigned int no_of_bytes) {
    
    int status = 0;
    unsigned int sect_offset = 0;
    char* file_pos = NULL;
    unsigned char no_of_sections = '\0';

    // Input validation
    if (shm_ref ==  NULL) {
        LOG("invalid parameter \"shm_ref\"");
    }
    if (file_ref == NULL) {
        LOG("invalid parameter \"file_ref\"")
    }

    // Get number of sections of the SF file
    file_pos = file_ref + 8;
    no_of_sections = *file_pos;

    // Check if section_no is valid
    if (section_no > no_of_sections) {
        INFO("invalid section_no");
        status = -1;
        goto cleanup;
    }
    
    // Iterate through section headers until the section_no header is reached
    file_pos = file_pos + 1;
    for (int i = 1; i < section_no; i++) {
        file_pos = file_pos + 25;
    }    

    // Get section offset
    file_pos = file_pos + 17;
    sect_offset = *((unsigned int*) file_pos);

    // Copy no_of_bytes from the offset in the section_no into the beginning of the memory mapped shared memory object
    memcpy(shm_ref, file_ref + sect_offset + offset, no_of_bytes);

cleanup:

    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}

/**
 * @brief Reads a specified number of bytes from a logical offset of an SF file mapped into memory and writes them into the beginning of a shared memory region mapped into memory
 * 
 * @param resp_fd - file descriptor of the response pipe
 * @param shm_ref - reference to the shared memory region mapped into mmemory
 * @param file_ref - reference to the SF file mapped into memory
 * @param file_size - size of the SF file mapped into memory 
 * @param logical_offset - logical offset of the SF file from which to read the bytes
 * @param no_of_bytes - number of bytes to be read from the SF file and written into the shared memory region
 */
void read_from_logical_space_offset(int resp_fd, char* shm_ref, char* file_ref, int file_size, unsigned int logical_offset, unsigned int no_of_bytes) {
    
    int status = 0, section_no = -1, page_no = -1, section_offset = -1;
    int* section_start = NULL;
    char* file_pos = NULL;
    unsigned char no_of_sections = '\0';
    SECT_DATA* sect_data = NULL;
    
    // Input validation
    if (shm_ref ==  NULL) {
        LOG("invalid parameter \"shm_ref\"");
    }
    if (file_ref == NULL) {
        LOG("invalid parameter \"file_ref\"")
    }

    // Get the number of sections in the SF file
    file_pos = file_ref + 8;
    no_of_sections = *file_pos;

    if (no_of_sections < 1) {
        LOG("invalid number of sections");
    }

    // Create an array that remembers at what page (block of 5120 bytes) each section starts
    // section_start[i] = x means that section number i + 1 starts at offset x in the logical memory space
    section_start = (int*) malloc(no_of_sections * sizeof(int));
    if (NULL == section_start) {
        LOG("could not allocate memory");
    }
    // First section starts at logical memory offset 0
    section_start[0] = 0;

    // Allocate memory for an array of SECT_DATA
    sect_data = (SECT_DATA*) malloc(no_of_sections * sizeof(SECT_DATA));
    if (NULL == sect_data) {
        LOG("could not allocate memroy");
    }

    // Get the sections offsets and sizes from the SF file
    file_pos = file_pos + 1;
    for (int i = 0; i < no_of_sections; i++) {
        // Move to the beginning of sect_offset
        file_pos = file_pos + 17;

        // Read the section data (offset and size)
        sect_data[i] = *((SECT_DATA*) file_pos);
        
        // Move to the end of the section header
        file_pos = file_pos + 8;
    }

    // Fill the section_start array
    for (int i = 1; i < no_of_sections; i++) {
        section_start[i] = section_start[i-1] + sect_data[i-1].size / PAGE_SIZE + 1;
    }

    // Get the page number that contains the logical ofsset provided
    page_no = logical_offset / PAGE_SIZE;

    // Find the section that is loaded at the page pointed to by the logical offset
    for (int i = 0; i < no_of_sections; i++) {
        if (section_start[i] == page_no) {
            section_no = i;
            break;
        }
    }
    if (section_no == -1) {
        INFO("logical_offset doesn't map to SF file's content");
        status = -1;
        goto cleanup;
    }

    // Get the offset from the beginning of the desired section from which to read the bytes
    section_offset = logical_offset % PAGE_SIZE;

    // Copy the specified number of bytes from the SF file into the beginning of the memory mapped shared memory object
    memcpy(shm_ref, file_ref + sect_data[section_no].offset + section_offset, no_of_bytes);

cleanup:

    // Free section_start vector
    if (NULL != section_start) {
        free(section_start);
    }
    else {
        LOG("undexpected NULL pointer of memory that hasn't been freed");
    }

    // Free sect_data vector
    if (NULL != sect_data) {
        free(sect_data);
    }
    else {
        LOG("unexpected NULL pointer of memory that hasn't been freed");
    }

    // Write status response on the response pipe 
    wrstat_resp_pipe(resp_fd, status);
}

/**
 * @brief Executes commands received from another process through a pipe file
 * 
 * @param resp_fd - file descriptor of the response pipe 
 * @param req_fd - file descriptor of the request pipe
 */
void execute_commands(int resp_fd, int req_fd) 
{
    int bytes_read = 0, file_size = -1;
    char cmd[BUFFSIZE];
    char* file_ref = NULL, *shm_ref = NULL;
    unsigned char cmd_size = '\0';

    while(1) 
    {
        // Read the size of the command
        bytes_read = read(req_fd, &cmd_size, 1);
        if (bytes_read != 1) {
            LOG("cmd_size read incorrectly");
        }

        // Read the command
        bytes_read = read(req_fd, cmd, cmd_size);
        if(bytes_read != cmd_size) {
            LOG("cmd read incorrectly");
        }
        cmd[bytes_read] = '\0';
        // setbuf(stdout, NULL); - alternative for the line of code above
        
        if      (strcmp(cmd, "PING") == 0) {
            // Execute command
            ping(resp_fd);
        } 
        else if (strcmp(cmd, "CREATE_SHM") == 0) {
            unsigned int shm_size = 0;

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x0A" "CREATE_SHM", 11);

            // Read the size of the shared memory object
            bytes_read = read(req_fd, &shm_size, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("shm_size read incorrectly");
            }

            // Execute command
            create_shm(resp_fd, &shm_ref);
        }
        else if (strcmp(cmd, "WRITE_TO_SHM") == 0) {
            unsigned int offset= 0, value = 0;

            // Wite the appropriate message on the response pipe
             write(resp_fd, "\x0C" "WRITE_TO_SHM", 13);

            // Read the offset
            bytes_read = read(req_fd, &offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("offset read incorrectly");
            }

            // Read the value
            bytes_read = read(req_fd, &value, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("value read incorrectly");
            }

            // Execute command
            write_to_shm(resp_fd, shm_ref, offset, value);
        }
        else if (strcmp(cmd, "MAP_FILE") == 0) {
            char file_name[BUFFSIZE];
            unsigned char size = '\0';

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x08" "MAP_FILE", 9);

            // Read size of the file name
            bytes_read = read(req_fd, &size, 1);
            if (bytes_read != 1) {
                LOG("file name size read incorrectly");
            }

            // Read file name
            bytes_read = read(req_fd, file_name, size);
            if (bytes_read != size) {
                LOG("file name read incorrectly");
            }
            file_name[bytes_read] = '\0';
            
            // Execute command
            map_file(resp_fd, &file_ref, &file_size, file_name);
        }
        else if (strcmp(cmd, "READ_FROM_FILE_OFFSET") == 0) {
            unsigned int offset = 0, no_of_bytes = 0;

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x15" "READ_FROM_FILE_OFFSET", 22);

            // Read the offset
            bytes_read = read(req_fd, &offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("offset read incorrectly");
            }
            
            // Read the number of bytes
            bytes_read = read(req_fd, &no_of_bytes, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("nr_of_bytes read incorrectly");
            }

            // Execute command
            read_from_file_offset(resp_fd, shm_ref, file_ref, file_size, offset, no_of_bytes);
        }
        else if (strcmp(cmd, "READ_FROM_FILE_SECTION") == 0) {
            unsigned int section_no = 0, offset = 0, no_of_bytes = 0;

            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x16" "READ_FROM_FILE_SECTION", 23);

            // Read section number
            bytes_read = read(req_fd, &section_no, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("section_no read incorrectly");
            }

            // Read offset
            bytes_read = read(req_fd, &offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("offset read incorrectly");
            }

            // Read number of bytes
            bytes_read = read(req_fd, &no_of_bytes, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("nr_of_bytes read incorrectly");
            }

            // Execute command
            read_from_file_section(resp_fd, shm_ref, file_ref, file_size, section_no, offset, no_of_bytes);
        }
        else if (strcmp(cmd, "READ_FROM_LOGICAL_SPACE_OFFSET") == 0) {
            unsigned int logical_offset = 0, no_of_bytes = 0;
            
            // Wite the appropriate message on the response pipe
            write(resp_fd, "\x1E" "READ_FROM_LOGICAL_SPACE_OFFSET", 31);

            // Read logical offset
            bytes_read = read(req_fd, &logical_offset, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("section_no read incorrectly");
            }

            // Read number of bytes
            bytes_read = read(req_fd, &no_of_bytes, sizeof(unsigned int));
            if (bytes_read != sizeof(unsigned int)) {
                LOG("section_no read incorrectly");
            }

            // Execute command
            read_from_logical_space_offset(resp_fd, shm_ref, file_ref, file_size, logical_offset, no_of_bytes);
        }
        else if (strcmp(cmd, "EXIT") == 0) {
            // Close shared memory
            if (shm_ref != NULL) {
                munmap(shm_ref, SHM_SIZE);
                shm_ref = NULL;
            }

            // Close mapped file
            if (file_ref != NULL) {
                munmap(file_ref, file_size);
                file_ref = NULL;
            }

            // Close the connection (request pipe)
            close(req_fd);

            // Close and remove the response pipe
            close(resp_fd);
            unlink(RESP_PIPE);

            // Exit the function and the program 
            return;
        }
    }
}

/**
 * @brief Establishes a connection with another process through pipes
 * 
 * @param resp_fd - output parameter that will be the file descriptor of the response pipe (the pipe on which this program writes the responses to the commands received)
 * @param req_fd - output parameter that will be the file descriptor of the request pipe (the pipe from which this program reads the commands)
 */
void connect(int* resp_fd, int* req_fd) 
{
    // Create a response pipse with permissions for writing
    mkfifo(RESP_PIPE, 0666);

    // Open the request pipe, created by the tester, for reading
    *req_fd = open(REQ_PIPE, O_RDWR);
    if (*req_fd < 3) {
        LOG("ERROR\ncannot open the request pipe");
    }

    // Opens the response pipe for writing
    *resp_fd = open(RESP_PIPE, O_RDWR);
    if (*resp_fd < 3) {
        LOG("ERROR\ncannot create the response pipe");
    }

    // Write "CONNECT" on the response pipe
    write(*resp_fd, "\x07" "CONNECT", 8);

    // Display sucess message on the screen
    printf("SUCCESS\n");
}

int main() 
{
    int resp_fd = -1, req_fd = -1;

    connect(&resp_fd, &req_fd);
    execute_commands(resp_fd, req_fd);

    return 0;
}