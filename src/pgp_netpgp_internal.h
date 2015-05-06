#pragma once

#include <curl/curl.h>

typedef struct _pEpNetPGPSession {
    CURL *curl;
} pEpNetPGPSession;
