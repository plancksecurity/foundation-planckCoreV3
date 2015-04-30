#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <strings.h>
#include <sys/select.h>

#ifdef __IPHONE_OS_VERSION_MAX_ALLOWED
#define USE_NETPGP
#endif

#ifdef __cplusplus
extern "C" {
#endif

const char *unix_local_db(void);
const char *gpg_conf(void);
const char *gpg_home(void);

#ifdef __cplusplus
}
#endif
