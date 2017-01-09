// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include <curl/curl.h>
#include <pthread.h>

typedef struct _pEpNetPGPSession {
    pthread_mutex_t curl_mutex;
} pEpNetPGPSession;
