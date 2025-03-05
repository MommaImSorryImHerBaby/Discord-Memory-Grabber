#define _CRT_SECURE_NO_WARNINGS

#include "include/webhooks.hpp"
#include <iostream>
// libcurlx64
#include <curl/curl.h>
// JSON serializer
#include <nlohmann/json.hpp>


size_t Webhook::write_callback(void* ptr, size_t size, size_t nmemb, void* data) {
	// write callback 4 stdout
	return size * nmemb;
}

bool Webhook::verify_url(std::string url) {
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

// constructor redefinition
Webhook::Webhook(std::string url, std::string username, std::string avatar_url) {
	// discord webhook support!
	// check if url is empty & valid
    if (!url.empty() && this->verify_url(url))
        this->url = url;

    if (!avatar_url.empty() && this->verify_url(avatar_url))
    { // check url and add to instance & payload
        this->payload["avatar_url"] = avatar_url;
        this->avatar_url = avatar_url;
    }

    if (!username.empty()) // add username 2 payload
        this->payload["username"] = username;
}

bool Webhook::execute(std::string content) {
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
