#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <cstdlib>
#include <signal.h>

bool runAsRoot() {
    if (geteuid() != 0) {
        std::cerr << "This program requires root privileges to run properly." << std::endl;
        return false;
    }
    return true;
}

void listProcesses(bool fullList) {
    DIR* dir;
    struct dirent* entry;

    dir = opendir("/proc");
    if (!dir) {
        std::cerr << "Failed to open /proc directory: " << strerror(errno) << std::endl;
        return;
    }

    std::cout << "PID\t| Process Name" << std::endl;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && std::isdigit(entry->d_name[0])) {
            std::string pid = entry->d_name;
            std::string status_path = "/proc/" + pid + "/status";
            std::ifstream status_file(status_path);
            std::string line;
            std::string name;

            while (std::getline(status_file, line)) {
                if (line.substr(0, 6) == "Name:\t") {
                    name = line.substr(6);
                    break;
                }
            }

            if (!fullList) {
                std::cout << pid << "\t| " << name << std::endl;
            } else {
                std::ifstream cmdline_file("/proc/" + pid + "/cmdline");
                std::getline(cmdline_file, line, '\0');
                std::cout << pid << "\t| " << line << std::endl;
            }
        }
    }

    closedir(dir);
}

void killProcessByPID(pid_t processId) {
    if (kill(processId, SIGKILL) == 0) {
        std::cout << "Process " << processId << " terminated successfully." << std::endl;
    } else {
        std::cerr << "Failed to terminate process " << processId << ": " << strerror(errno) << std::endl;
    }
}

void killProcessByName(const std::string& processName) {
    DIR* dir;
    struct dirent* entry;

    dir = opendir("/proc");
    if (!dir) {
        std::cerr << "Failed to open /proc directory: " << strerror(errno) << std::endl;
        return;
    }

    std::cout << "PID\t| Process Name" << std::endl;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && std::isdigit(entry->d_name[0])) {
            std::string pid = entry->d_name;
            std::string status_path = "/proc/" + pid + "/status";
            std::ifstream status_file(status_path);
            std::string line;
            std::string name;

            while (std::getline(status_file, line)) {
                if (line.substr(0, 6) == "Name:\t") {
                    name = line.substr(6);
                    break;
                }
            }

            if (name == processName) {
                if (kill(std::stoi(pid), SIGKILL) == 0) {
                    std::cout << "Process " << pid << " (" << processName << ") terminated successfully." << std::endl;
                } else {
                    std::cerr << "Failed to terminate process " << pid << " (" << processName << "): " << strerror(errno) << std::endl;
                }
            }
        }
    }

    closedir(dir);
}

void killProcessByPath(const std::string& processPath) {
    DIR* dir;
    struct dirent* entry;

    dir = opendir("/proc");
    if (!dir) {
        std::cerr << "Failed to open /proc directory: " << strerror(errno) << std::endl;
        return;
    }

    std::cout << "PID\t| Process Name" << std::endl;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && std::isdigit(entry->d_name[0])) {
            std::string pid = entry->d_name;
            std::string exe_path = "/proc/" + pid + "/exe";
            char buf[4096];
            ssize_t len = readlink(exe_path.c_str(), buf, sizeof(buf) - 1);
            if (len != -1) {
                buf[len] = '\0';
                std::string path(buf);
                if (path == processPath) {
                    if (kill(std::stoi(pid), SIGKILL) == 0) {
                        std::cout << "Process " << pid << " (" << processPath << ") terminated successfully." << std::endl;
                    } else {
                        std::cerr << "Failed to terminate process " << pid << " (" << processPath << "): " << strerror(errno) << std::endl;
                    }
                }
            }
        }
    }

    closedir(dir);
}

int main() {
    if (!runAsRoot()) {
        return 1;
    }

    std::cout << "Do you want to see the full command line or just the name of the processes?" << std::endl;
    std::cout << "Enter 'full' to see the full command line or 'name' to see only the name: ";
    std::string choice;
    std::cin >> choice;

    bool fullList = (choice == "full");

    listProcesses(fullList);

    std::cout << "Do you want to kill any process?" << std::endl;
    std::cout << "Enter 'pid' to kill by PID, 'name' to kill by process name, or 'path' to kill by process path: ";
    std::string killChoice;
    std::cin >> killChoice;

    if (killChoice == "pid") {
        std::cout << "Enter the PID of the process to kill: ";
        pid_t processId;
        std::cin >> processId;
        killProcessByPID(processId);
    } else if (killChoice == "name") {
        std::cout << "Enter the name of the process to kill: ";
        std::string processName;
        std::cin >> processName;
        killProcessByName(processName);
    } else if (killChoice == "path") {
        std::cout << "Enter the path of the process to kill: ";
        std::string processPath;
        std::cin >> processPath;
        killProcessByPath(processPath);
    } else {
        std::cerr << "Invalid choice." << std::endl;
        return 1;
    }

    return 0;
}
