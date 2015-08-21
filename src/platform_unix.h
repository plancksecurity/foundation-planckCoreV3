#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <strings.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *unix_local_db(void);
const char *gpg_conf(void);
const char *gpg_home(void);

#ifdef ANDROID
char *stpcpy(char *dst, const char *src);
long int random(void);
#endif

#ifdef __cplusplus
}
#endif
