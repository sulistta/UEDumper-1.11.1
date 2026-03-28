// ReSharper disable CppNonInlineFunctionDefinitionInHeaderFile
#pragma once

#ifdef UEDUMPER_HEADLESS

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/*
██████╗░██╗░░░░░███████╗░█████╗░░██████╗███████╗  ██████╗░███████╗░█████╗░██████╗░██╗
██╔══██╗██║░░░░░██╔════╝██╔══██╗██╔════╝██╔════╝  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██████╔╝██║░░░░░█████╗░░███████║╚█████╗░█████╗░░  ██████╔╝█████╗░░███████║██║░░██║██║
██╔═══╝░██║░░░░░██╔══╝░░██╔══██║░╚═══██╗██╔══╝░░  ██╔══██╗██╔══╝░░██╔══██║██║░░██║╚═╝
██║░░░░░███████╗███████╗██║░░██║██████╔╝███████╗  ██║░░██║███████╗██║░░██║██████╔╝██╗
╚═╝░░░░░╚══════╝╚══════╝╚═╝░░╚═╝╚═════╝░╚══════╝  ╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚═════╝░╚═╝
*/

inline pid_t procHandle = -1;
inline int procMemFd = -1;
inline std::string attachedProcessName;
inline std::string attachedModulePath;

struct DriverRegion
{
    uint64_t start = 0;
    uint64_t end = 0;
    std::string perms;
    std::string path;
};

inline void init()
{
}

inline std::string trim(const std::string& value)
{
    const auto first = value.find_first_not_of(" \t");
    if (first == std::string::npos)
        return "";
    const auto last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1);
}

inline std::string basenameOf(const std::string& path)
{
    const auto pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

inline bool readSmallFile(const std::string& path, std::string& out, bool binary = false)
{
    std::ifstream file(path, binary ? std::ios::binary : std::ios::in);
    if (!file)
        return false;

    std::ostringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}

inline std::vector<DriverRegion> getProcessMappings(const int pid)
{
    std::vector<DriverRegion> regions;

    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line))
    {
        std::istringstream iss(line);
        std::string range;
        std::string perms;
        std::string offset;
        std::string dev;
        std::string inode;
        if (!(iss >> range >> perms >> offset >> dev >> inode))
            continue;

        DriverRegion region;
        region.perms = perms;

        const auto dash = range.find('-');
        if (dash == std::string::npos)
            continue;

        region.start = std::stoull(range.substr(0, dash), nullptr, 16);
        region.end = std::stoull(range.substr(dash + 1), nullptr, 16);

        std::string path;
        std::getline(iss, path);
        region.path = trim(path);
        regions.push_back(region);
    }

    return regions;
}

inline bool pathLooksLikeTarget(const std::string& path, const std::string& processName)
{
    if (path.empty() || processName.empty())
        return false;

    return basenameOf(path) == processName || path.find(processName) != std::string::npos;
}

inline std::string guessMainModulePath(const int pid, const std::string& processName)
{
    std::string bestPath;
    uint64_t bestBase = std::numeric_limits<uint64_t>::max();

    for (const auto& region : getProcessMappings(pid))
    {
        if (region.path.empty())
            continue;

        if (!pathLooksLikeTarget(region.path, processName))
            continue;

        if (region.start < bestBase)
        {
            bestBase = region.start;
            bestPath = region.path;
        }
    }

    if (!bestPath.empty())
        return bestPath;

    for (const auto& region : getProcessMappings(pid))
    {
        if (region.path.empty())
            continue;
        if (region.path.find(".exe") == std::string::npos)
            continue;

        if (region.start < bestBase)
        {
            bestBase = region.start;
            bestPath = region.path;
        }
    }

    return bestPath;
}

inline uint64_t getBaseAddressForPath(const int pid, const std::string& modulePath)
{
    uint64_t bestBase = 0;
    for (const auto& region : getProcessMappings(pid))
    {
        if (region.path != modulePath)
            continue;

        if (!bestBase || region.start < bestBase)
            bestBase = region.start;
    }
    return bestBase;
}

inline std::string narrowWide(const wchar_t* processName)
{
    if (!processName)
        return {};

    std::wstring ws(processName);
    return std::string(ws.begin(), ws.end());
}

inline bool processMatches(const int pid, const std::string& processName)
{
    if (processName.empty())
        return false;

    std::string cmdline;
    if (readSmallFile("/proc/" + std::to_string(pid) + "/cmdline", cmdline, true))
    {
        for (char& ch : cmdline)
        {
            if (ch == '\0')
                ch = ' ';
        }

        if (cmdline.find(processName) != std::string::npos)
            return true;
    }

    std::string comm;
    if (readSmallFile("/proc/" + std::to_string(pid) + "/comm", comm))
    {
        comm = trim(comm);
        if (comm == processName)
            return true;
    }

    return false;
}

inline int findProcessId(const std::string& processName)
{
    DIR* dir = opendir("/proc");
    if (!dir)
        return 0;

    int result = 0;
    while (const dirent* entry = readdir(dir))
    {
        if (!entry->d_name || !std::isdigit(entry->d_name[0]))
            continue;

        const int pid = std::atoi(entry->d_name);
        if (pid <= 0)
            continue;

        if (processMatches(pid, processName))
        {
            result = pid;
            break;
        }
    }

    closedir(dir);
    return result;
}

inline const std::string& getAttachedModulePath()
{
    return attachedModulePath;
}

inline void attachToProcess(const int& pid)
{
    procHandle = pid;
    if (procMemFd >= 0)
    {
        close(procMemFd);
        procMemFd = -1;
    }

    const std::string memPath = "/proc/" + std::to_string(pid) + "/mem";
    procMemFd = open(memPath.c_str(), O_RDONLY);
}

inline void loadData(std::string& processName, uint64_t& baseAddress, int& processID)
{
    attachedProcessName = processName;
    processID = findProcessId(processName);
    if (!processID)
    {
        baseAddress = 0;
        return;
    }

    attachedModulePath = guessMainModulePath(processID, processName);
    baseAddress = attachedModulePath.empty() ? 0 : getBaseAddressForPath(processID, attachedModulePath);
    attachToProcess(processID);
}

inline void _read(const void* address, void* buffer, const DWORD64 size)
{
    if (procHandle <= 0)
        return;

    size_t bytesRead = 0;
    bool success = false;
    for (size_t amount = size; amount > 0 && !success; amount = amount > 16 ? amount - 16 : 0)
    {
        struct iovec local { buffer, amount };
        struct iovec remote { const_cast<void*>(address), amount };
        const ssize_t n = process_vm_readv(procHandle, &local, 1, &remote, 1, 0);
        if (n == static_cast<ssize_t>(amount))
        {
            bytesRead = static_cast<size_t>(n);
            success = true;
        }
        if (amount <= 16)
            break;
    }

    if (!success && procMemFd >= 0)
    {
        if (pread(procMemFd, buffer, size, static_cast<off_t>(reinterpret_cast<uintptr_t>(address))) == static_cast<ssize_t>(size))
            bytesRead = size;
    }

    if (bytesRead < size)
        std::memset(static_cast<char*>(buffer) + bytesRead, 0, size - bytesRead);
}

inline void _write(void* address, const void* buffer, const DWORD64 size)
{
    if (procHandle <= 0)
        return;

    struct iovec local { const_cast<void*>(buffer), size };
    struct iovec remote { address, size };
    process_vm_writev(procHandle, &local, 1, &remote, 1, 0);
}

inline uint64_t _getBaseAddress(const wchar_t* processName, int& pid)
{
    if (pid <= 0)
    {
        const std::string narrowed = narrowWide(processName);
        if (narrowed.empty())
            return 0;

        pid = findProcessId(narrowed);
        attachedProcessName = narrowed;
    }

    if (pid <= 0)
        return 0;

    if (attachedModulePath.empty())
        attachedModulePath = guessMainModulePath(pid, attachedProcessName);

    if (attachedModulePath.empty())
        return 0;

    return getBaseAddressForPath(pid, attachedModulePath);
}

#else

//add any other includes here your driver might use
#include <Windows.h>
#include <tlhelp32.h>

/*
██████╗░██╗░░░░░███████╗░█████╗░░██████╗███████╗  ██████╗░███████╗░█████╗░██████╗░██╗
██╔══██╗██║░░░░░██╔════╝██╔══██╗██╔════╝██╔════╝  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██████╔╝██║░░░░░█████╗░░███████║╚█████╗░█████╗░░  ██████╔╝█████╗░░███████║██║░░██║██║
██╔═══╝░██║░░░░░██╔══╝░░██╔══██║░╚═══██╗██╔══╝░░  ██╔══██╗██╔══╝░░██╔══██║██║░░██║╚═╝
██║░░░░░███████╗███████╗██║░░██║██████╔╝███████╗  ██║░░██║███████╗██║░░██║██████╔╝██╗
╚═╝░░░░░╚══════╝╚══════╝╚═╝░░╚═╝╚═════╝░╚══════╝  ╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚═════╝░╚═╝
*/

//global variables here
HANDLE procHandle = nullptr;

//in case you need to initialize anything BEFORE your com works, you can do this in here.
//this function IS NOT DESIGNED to already take the process name as input or anything related to the target process
//use the function "load" below which will contain data about the process name
inline void init()
{
    //...
}

uint64_t _getBaseAddress(const wchar_t* processName, int& pid);

void attachToProcess(const int& pid);

/**
 * \brief use this function to initialize the target process
 * \param processName process name as input
 * \param baseAddress base address of the process gets returned
 * \param processID process id of the process gets returned
 */
inline void loadData(std::string& processName, uint64_t& baseAddress, int& processID)
{
    const auto name = std::wstring(processName.begin(), processName.end());

    baseAddress = _getBaseAddress(name.c_str(), processID);

    attachToProcess(processID);
}

/**
 * \brief read function (replace with your read logic)
 * \param address memory address to read from
 * \param buffer memory address to write to
 * \param size size of memory to read (expects the buffer/address to have this size too)
 */
inline void _read(const void* address, void* buffer, const DWORD64 size)
{
    size_t bytes_read = 0;
    BOOL b = ReadProcessMemory(procHandle, address, buffer, size, &bytes_read);
    //if failed, try with lower byte amount
    if (!b)
    {
        //always read 10 bytes lower
        for (int i = 1; i < size && !b; i += 10)
        {
            b = ReadProcessMemory(procHandle, address, buffer, size - i, nullptr);
        }
    }
}


/**
 * \brief write function (replace with your write logic)
 * \param address memory address to write to
 * \param buffer memory address to write from
 * \param size size of memory to write (expects the buffer/address to have this size too)
 */
inline void _write(void* address, const void* buffer, const DWORD64 size)
{
    WriteProcessMemory(procHandle, address, buffer, size, nullptr);
}


/**
 * \brief gets the process base address. If you adjust the params, make sure to change them in memory.cpp too
 * \param processName the name of the process
 * \param pid returns the process id
 * \return process base address
 */
inline uint64_t _getBaseAddress(const wchar_t* processName, int& pid)
{
    uint64_t baseAddress = 0;

    if (!pid)
    {
        // Get a handle to the process
        const HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcess == INVALID_HANDLE_VALUE) {
            return false;
        }

        // Iterate through the list of processes to find the one with the given filename
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (!Process32First(hProcess, &pe32)) {
            CloseHandle(hProcess);
            return false;
        }
        while (Process32Next(hProcess, &pe32)) {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        }

        CloseHandle(hProcess);
    }

    // Get the base address of the process in memory
    if (pid != 0) {
        const HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hModule != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
            if (Module32First(hModule, &me32)) {
                baseAddress = reinterpret_cast<DWORD64>(me32.modBaseAddr);
            }
            CloseHandle(hModule);
        }
    }

    // Clean up and return

    return baseAddress;
}

/**
 * \brief this function might not be needed for your driver, this just attaches to the process
 * \param pid process id of the target process
 */
inline void attachToProcess(const int& pid)
{
    procHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
}

#endif
