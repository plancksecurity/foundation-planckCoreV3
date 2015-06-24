#pragma once

#include <curl/curl.h>
#include <pthread.h>

typedef struct _pEpNetPGPSession {
    pthread_mutex_t curl_mutex;
} pEpNetPGPSession;
