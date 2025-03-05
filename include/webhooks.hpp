#ifndef WEBHOOKS_H
#define WEBHOOKS_H

#include <iostream>
#include <nlohmann/json.hpp>

class Webhook {
public:
	std::string url;
	std::string avatar_url;

	nlohmann::json payload;

	static size_t write_callback(void* ptr, size_t size, size_t nmemb, void* data);
	bool	      verify_url(std::string url);
	// constructor
	Webhook(std::string url, std::string username = "", std::string avatar_url = "");
	// execute!
	bool execute(std::string content);
};

#endif 