/*
 * Copyright (c) 2017 Carter Yagemann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <fcntl.h>

#include <libvmi/libvmi.h>

#include <trace.h>
#include <config.h>
#include <monitor.h>
#include <dump.h>
#include <output.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

/* Global variables */
char *domain_name = NULL;
char *process_name = NULL;
char *vol_profile = NULL;
char *output_dir = NULL;
char *rekall = NULL;
vmi_pid_t process_pid = 0;
uint8_t tracking_flags = MONITOR_FOLLOW_REMAPPING;
char *config_file_path = NULL;
char *fifo_file_path = NULL;

static const char *default_config_path = "./unpack.cfg";

/* Signal handler */
static int interrupted = 0;
static struct sigaction action;
static sigset_t my_sigs;
static void close_handler(int sig)
{
    log_info("close_handler() called");
    interrupted = sig;
}

void usage(char *name)
{
    printf("%s [options]\n", name);
    printf("\n");
    printf("Required arguments:\n");
    printf("    -d <domain_name>         Name of VM to unpack from.\n");
    printf("    -r <rekall_file>         Path to rekall file.\n");
    printf("    -v <vol_profile>         Volatility profile to use.\n");
    printf("    -o <output_dir>          Directory to dump layers into.\n");
    printf("\n");
    printf("One of the following must be provided:\n");
    printf("    -p <pid>                 Unpack process with provided PID.\n");
    printf("    -n <process_name>        Unpack process with provided name.\n");
    printf("\n");
    printf("Recommended arguments:\n");
    printf("    -c                       Path to '[global]\\nkey=val' config file.\n");
    printf("Optional arguments:\n");
    printf("    -f                       Also follow children created by target process.\n");
    printf("    -l                       Monitor library, heap and stack pages. By default, these are ignored.\n");
    printf("    -i                       A fifo to write to signalling that the main loop started.\n");
}

event_response_t monitor_pid(vmi_instance_t vmi, vmi_event_t *event)
{

    vmi_pid_t pid = vmi_current_pid(vmi, event);
    if (pid == process_pid)
    {
        log_info("FOUND PARENT: PID %d", pid);
        // monitor_add_page_table(vmi, pid, process_layer, tracking_flags, 0);
        monitor_add_page_table(vmi, pid, volatility_callback_vaddump, tracking_flags, 0);
        monitor_remove_cr3(monitor_pid);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t monitor_name(vmi_instance_t vmi, vmi_event_t *event)
{

    char *name = vmi_current_name(vmi, event);
    if (name && !strncmp(name, process_name, strlen(name)))
    {
        vmi_pid_t pid = vmi_current_pid(vmi, event);
        process_pid = pid;
        log_info("FOUND PARENT: PID %d", pid);
        // monitor_add_page_table(vmi, pid, process_layer, tracking_flags, 0);
        monitor_add_page_table(vmi, pid, volatility_callback_vaddump, tracking_flags, 0);
        monitor_remove_cr3(monitor_name);
    }
    free(name);

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Monitors a process' page table.
 */
int main(int argc, char *argv[])
{
    int c;

    // Parse arguments
    while ((c = getopt(argc, argv, "d:r:v:o:p:n:c:i:fl")) != -1)
    {
        switch (c)
        {
            case 'd':
                domain_name = optarg;
                break;
            case 'r':
                rekall = optarg;
                break;
            case 'v':
                vol_profile = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'p':
                process_pid = atoi(optarg);
                break;
            case 'n':
                process_name = optarg;
                break;
            case 'c':
                config_file_path = optarg;
                break;
            case 'f':
                tracking_flags |= MONITOR_FOLLOW_CHILDREN;
                break;
            case 'l':
                tracking_flags |= MONITOR_HIGH_ADDRS;
                break;
            case 'i':
                fifo_file_path = optarg;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!config_file_path)
        config_file_path = (typeof(config_file_path))default_config_path;
    if (config_file_path)
    {
        if (!load_config_file(config_file_path))
        {
            //trace_config("config did not load: path=%s", config_file_path);
        }
        //once loaded, we can close it
        close_config_file();
        atexit(free_config);
    }

    if (!domain_name || !rekall || !vol_profile || !output_dir ||
        (process_pid == 0 && process_name == NULL))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // santity checks for volatility
    if (system("which volatility 2>&1 >/dev/null"))
    {
        log_error("ERROR: Unpack - volatility not found in path.");
        return EXIT_FAILURE;
    }

    // setup signal mask for worker threads, who will not be handling any signals
    sigemptyset(&my_sigs);
    sigaddset(&my_sigs, SIGTERM);
    sigaddset(&my_sigs, SIGHUP);
    sigaddset(&my_sigs, SIGINT);
    sigaddset(&my_sigs, SIGALRM);
    sigaddset(&my_sigs, SIGPIPE);
    // block these signals in main thread and other threads
    pthread_sigmask(SIG_BLOCK, &my_sigs, NULL);

    // start all child threads below
    start_dump_thread(output_dir);
    start_shell_thread();
    // end child thread creation

    // Register signal handler. only main thread will handle them.
    action.sa_handler = close_handler;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP,  &action, NULL);
    sigaction(SIGINT,  &action, NULL);
    sigaction(SIGALRM, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
    // unblock these signals in main thread
    pthread_sigmask(SIG_UNBLOCK, &my_sigs, NULL);

    // Initialize libVMI
    vmi_instance_t vmi;
    if (vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL,
                          VMI_CONFIG_JSON_PATH, rekall, NULL) == VMI_FAILURE)
    {
        log_error("ERROR: libVMI - Failed to initialize libVMI.");
        if (vmi != NULL)
        {
            //vmi_destroy(vmi);
        }
        return EXIT_FAILURE;
    }

    if (monitor_init(vmi))
    {
        log_error("ERROR: Unpack - Failed to initialize monitor");
        vmi_destroy(vmi);
        return EXIT_FAILURE;
    }

    if (process_name != NULL)
    {
        monitor_add_cr3(monitor_name);
    }
    else if (process_pid > 0)
    {
        monitor_add_cr3(monitor_pid);
    }

    // Initialize various helper methods
    if (!process_vmi_init(vmi, rekall))
    {
        log_error("ERROR: Unpack - Failed to initialize process VMI");
        monitor_destroy(vmi);
        vmi_destroy(vmi);
        stop_dump_thread();
        stop_shell_thread();
        return EXIT_FAILURE;
    }

    int fifo_fd;
    if (fifo_file_path && (fifo_fd = open(fifo_file_path, O_WRONLY)))
    {
        log_info("opened fifo %s", fifo_file_path);
        close(fifo_fd);
    }

    // Main loop
    status_t status;
    while (!interrupted)
    {
        status = vmi_events_listen(vmi, 500);
        if (status != VMI_SUCCESS)
        {
            log_error("ERROR: libVMI - Unexpected error while waiting for VMI events, quitting.");
            interrupted = 1;
        }

        // Exit if all our watched processes have exited
        if (process_pid)
        {
            if (g_hash_table_size(vmi_events_by_pid) == 0)
            {
                interrupted = 1;
            }
        }
    }

    // Cleanup
    stop_dump_thread();
    log_debug("dump thread stopped");
    stop_shell_thread();
    monitor_destroy(vmi);
    process_vmi_destroy(vmi);

    vmi_destroy(vmi);
    log_info("doing clean exit");
    return EXIT_SUCCESS;
}
