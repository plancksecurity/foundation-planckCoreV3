/**
 * @file    log.c
 * @brief   pEp logging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#define _EXPORT_PEP_ENGINE_DLL
#include "pEp_log.h"

#include "pEp_internal.h"
#include "timestamp.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>

#if defined (PEP_HAVE_SYSLOG)
#   include <syslog.h>
#endif

#if defined (PEP_HAVE_ANDROID_LOG)
#   include <android/log.h>
#endif

#if defined (PEP_HAVE_WINDOWS_LOG)
#   include <debugapi.h>
#endif


/* Initialisation and finalisation
 * ***************************************************************** */

/* Print a warning about enabled but unsupported destinations.  This will be
   executed once at startup. */
static void warn_about_unsupported_destinations(void) {
#if ! defined (PEP_HAVE_STDOUT_AND_STDERR)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDOUT)
        fprintf(stderr, "Warning: stdout logging selected but unavailable\n");
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDERR)
        fprintf(stderr, "Warning: stderr logging selected but unavailable\n");
#endif
    /* The database destination is always available. */
#if ! defined (PEP_HAVE_SYSLOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_SYSLOG)
        fprintf(stderr, "Warning: syslog logging selected but unavailable\n");
#endif
#if ! defined (PEP_HAVE_ANDROID_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_ANDROID)
        fprintf(stderr, "Warning: Android logging selected but unavailable\n");
#endif
#if ! defined (PEP_HAVE_WINDOWS_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_WINDOWS)
        fprintf(stderr, "Warning: windows logging selected but unavailable\n");
#endif
}

PEP_STATUS pEp_log_initialize(PEP_SESSION session)
{
    warn_about_unsupported_destinations();
    return PEP_STATUS_OK;
}

PEP_STATUS pEp_log_finalize(PEP_SESSION session)
{
    return PEP_STATUS_OK;
}


/* GNU/BSD formatted output emulation
 * ***************************************************************** */

static int pEp_vasprintf(char **string_pointer, const char *template,
                         va_list args)
{
    /* Sanity check. */
    assert(string_pointer != NULL);

    /* As an extension out of defensiveness we can also accept a NULL
       template. */
    if (template == NULL)
        template = "(null)";

    /* This is not performance-critical and we can afford doing the job twice,
       instead of first tentatively allocating a string that might or might not
       be big enough.
       So the idea is:
       1. first call vsnprintf giving a limit of 0 chars to be written, just to
          have its result value which is the required string size (minus one
          character for the trailing '\0');
       2. allocate a string with the right size;
       3. call vsnprintf once more, filling the string. */

    /* Since the va_list pointer (but not the pointed argument) is destroyed by
       each use (See the GNU C Library manual, §{"Variable Arguments Output
       Functions"}) I need a second copy of the pointer. */
    va_list args_copy;
    va_copy(args_copy, args);

    /* 1. Compute how many chars I need. */
    int needed_char_no = (vsnprintf(NULL, 0, template, args)
                          + /* for the trailing '\0' */ 1);
    va_end(args);

    /* 2. Allocate the string. */
    * string_pointer = malloc(needed_char_no);
    if (* string_pointer == NULL) {
        va_end(args_copy);
        return -1;
    }

    /* 3. Do the actual printing.  The string is now guaranteed to have
       sufficient size.  If I arrived at this point failure is no longer
       possible. */
    int res = vsnprintf(* string_pointer, needed_char_no, template, args_copy);
    va_end(args_copy);
    return res;
}

int pEp_asprintf(char **string_pointer, const char *template, ...)
{
    /* This is a simple wrapper around pEp_vasprintf, which does the actual
       work. */
    va_list ap;
    va_start(ap, template);
    int res = pEp_vasprintf(string_pointer, template, ap);
    va_end(ap);
    return res;
}


/* Logging facility: internal functionality
 * ***************************************************************** */

/* Given a log level return its printed representation */
static const char* _log_level_to_string(PEP_LOG_LEVEL level)
{
    switch (level) {
    case PEP_LOG_LEVEL_CRITICAL:    return "CRITICAL";
    case PEP_LOG_LEVEL_ERROR:       return "ERROR";
    case PEP_LOG_LEVEL_WARNING:     return "wng";
    case PEP_LOG_LEVEL_EVENT:       return "evt";
    case PEP_LOG_LEVEL_API:         return "api";
    case PEP_LOG_LEVEL_FUNCTION:    return "fnc";
    case PEP_LOG_LEVEL_TRACE:       return "trc";
    case PEP_LOG_LEVEL_EVERYTHING:  return "[everything log level (not for entries)]";
    default:                        return "invalid log level";
    }
}

/* The template string and arguments used by every destination relying on a
   printf-like API.  This expands to a string literal with no trailing newline
   character and no parentheses around. */
#define PEP_LOG_PRINTF_FORMAT                                 \
    "%04i-%02i-%02i %02i:%02i:%02i" /* date, time */          \
    "%s" PEP_LOG_PRINTF_FORMAT_NO_DATE

/* The variadic arguments to be passed after the template PEP_LOG_PRINTF_FORMAT
   .  This expands to a sequence of expressions separated by commas.  Notice
   newline separators here, that match line separators in PEP_LOG_PRINTF_FORMAT
   . */
#define PEP_LOG_PRINTF_ACTUALS                                    \
    time->tm_year + 1900, time->tm_mon + 1, time->tm_mday,        \
    time->tm_hour, time->tm_min, time->tm_sec,                    \
    system_subsystem_prefix, PEP_LOG_PRINTF_ACTUALS_NO_DATE


/* Like PEP_LOG_PRINTF_FORMAT and PEP_LOG_PRINTF_ACTUALS, but with
   different fields. */
#define PEP_LOG_PRINTF_FORMAT_NO_DATE                         \
    "%s%s%s"                      /* system, subsystem */   \
    " %li"                          /* pid */                 \
    " %s"                           /* log level */           \
    " %s:%i%s%s"                    /* source location */     \
    "%s%s"                          /* entry */
#define PEP_LOG_PRINTF_ACTUALS_NO_DATE                            \
    system, system_subsystem_separator,  \
        subsystem,                                                \
    (long) pid,                                                   \
    _log_level_to_string(level),                                  \
    source_file_name, source_file_line, function_prefix,          \
        function_name,                                            \
    entry_prefix, entry


/* Logging facility: FILE* destinations
 * ***************************************************************** */

/* The implementation of pEp_log for FILE * destinations. */
static PEP_STATUS _pEp_log_file_star(FILE* file_star,
                                     PEP_SESSION session,
                                     PEP_LOG_LEVEL level,
                                     const timestamp *time,
                                     pid_t pid,
                                     const char *system_subsystem_prefix,
                                     const char *system,
                                     const char *system_subsystem_separator,
                                     const char *subsystem,
                                     const char *source_file_name,
                                     int source_file_line,
                                     const char *function_prefix,
                                     const char *function_name,
                                     const char *entry_prefix,
                                     const char *entry)
{
    int fprintf_result = fprintf(file_star,
                                 PEP_LOG_PRINTF_FORMAT "\n",
                                 PEP_LOG_PRINTF_ACTUALS);
    if (fprintf_result < 0)
        return PEP_UNKNOWN_ERROR;
    else
        return PEP_STATUS_OK;
}


/* Logging facility: syslog destination
 * ***************************************************************** */

#if defined (PEP_HAVE_SYSLOG)
/* Given a pEp log level return its syslog equivalent, as the value to be
   passed as the first argument to the syslog function. */
static int _log_level_to_syslog_facility_priority(PEP_LOG_LEVEL level)
{
    int facility = LOG_USER;
#define RETURN_SYSLOG_PRIORITY(priority) \
    do { return LOG_MAKEPRI(facility, (priority)); } while (false)

    switch (level) {
    case PEP_LOG_LEVEL_CRITICAL:
        RETURN_SYSLOG_PRIORITY(LOG_CRIT);
    case PEP_LOG_LEVEL_ERROR:
        RETURN_SYSLOG_PRIORITY(LOG_ERR);
    case PEP_LOG_LEVEL_WARNING:
        RETURN_SYSLOG_PRIORITY(LOG_WARNING);
    case PEP_LOG_LEVEL_EVENT:
        RETURN_SYSLOG_PRIORITY(LOG_NOTICE);
    case PEP_LOG_LEVEL_API:
        RETURN_SYSLOG_PRIORITY(LOG_NOTICE);
    case PEP_LOG_LEVEL_FUNCTION:
        RETURN_SYSLOG_PRIORITY(LOG_INFO);
    case PEP_LOG_LEVEL_TRACE:
        RETURN_SYSLOG_PRIORITY(LOG_DEBUG);
    case PEP_LOG_LEVEL_EVERYTHING:
        /* This should not happen.  Let us make the log entry visible. */
        RETURN_SYSLOG_PRIORITY(LOG_DEBUG);
    default:
        /* Invalid.  Let us make the log entry visible. */
        RETURN_SYSLOG_PRIORITY(LOG_EMERG);
    }
#undef RETURN
}

/* The implementation of pEp_log for the syslog destination. */
static PEP_STATUS _pEp_log_syslog(PEP_SESSION session,
                                  PEP_LOG_LEVEL level,
                                  const timestamp *time,
                                  pid_t pid,
                                  const char *system_subsystem_prefix,
                                  const char *system,
                                  const char *system_subsystem_separator,
                                  const char *subsystem,
                                  const char *source_file_name,
                                  int source_file_line,
                                  const char *function_prefix,
                                  const char *function_name,
                                  const char *entry_prefix,
                                  const char *entry)
{
    int facility_priority
        = _log_level_to_syslog_facility_priority(level);
    syslog(facility_priority, PEP_LOG_PRINTF_FORMAT_NO_DATE,
           PEP_LOG_PRINTF_ACTUALS_NO_DATE);
    return PEP_STATUS_OK;
}
#endif /* #if defined (PEP_HAVE_SYSLOG) */


/* Logging facility: Android destination
 * ***************************************************************** */

#if defined (PEP_HAVE_ANDROID_LOG)
/* positron: this code is completely untested.  I read
     https://android.googlesource.com/platform/system/core/+/jb-dev/include/android/log.h
   and tried to do something reasonable, based on the (tested and working)
   syslog destination. */

/* Given a pEp log level return its enum android_LogPriority equivalent, as the
   value to be passed as the first argument to the __android_log_print
   function. */
static enum android_LogPriority _log_level_to_android_logpriority(
   PEP_LOG_LEVEL level)
{
    int facility = LOG_USER;
#define RETURN_ANDROID_LOGPRIORITY(priority) \
    do { return LOG_MAKEPRI(facility, (priority)); } while (false)

    switch (level) {
    case PEP_LOG_LEVEL_CRITICAL:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_FATAL);
    case PEP_LOG_LEVEL_ERROR:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_ERROR);
    case PEP_LOG_LEVEL_WARNING:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_WARN);
    case PEP_LOG_LEVEL_EVENT:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_INFO);
    case PEP_LOG_LEVEL_API:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_INFO);
    case PEP_LOG_LEVEL_FUNCTION:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_DEBUG);
    case PEP_LOG_LEVEL_TRACE:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_DEBUG);
    /* This should not happen. */
    case PEP_LOG_LEVEL_EVERYTHING:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_UNKNOWN);
    /* Invalid. */
    default:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_UNKNOWN);
    }
#undef RETURN
}

/* The implementation of pEp_log for the android_log destination. */
static PEP_STATUS _pEp_log_android_log(PEP_SESSION session,
                                       PEP_LOG_LEVEL level,
                                       const timestamp *time,
                                       pid_t pid,
                                       const char *system_subsystem_prefix,
                                       const char *system,
                                       const char *system_subsystem_separator,
                                       const char *subsystem,
                                       const char *source_file_name,
                                       int source_file_line,
                                       const char *function_prefix,
                                       const char *function_name,
                                       const char *entry_prefix,
                                       const char *entry)
{
    int prio = _log_level_to_android_logpriority(level);
    __android_log_print(prio, (system != NULL ? system : "pEp"),
                        PEP_LOG_PRINTF_FORMAT,
                        PEP_LOG_PRINTF_ACTUALS);
    return PEP_STATUS_OK;
}
#endif /* #if defined (PEP_HAVE_ANDROID_LOG) */


/* Logging facility: windows destination
 * ***************************************************************** */

#if defined (PEP_HAVE_WINDOWS_LOG)
/* positron: this code is completely untested.  I read
     http://www.unixwiz.net/techtips/outputdebugstring.html
   and the previously existing code in
     platform_windows.cpp
   and tried to do something reasonable, based on the other tested and working
   destinations. */

/* The implementation of pEp_log for the windows_log destination. */
static PEP_STATUS _pEp_log_windows_log(PEP_SESSION session,
                                       PEP_LOG_LEVEL level,
                                       const timestamp *time,
                                       pid_t pid,
                                       const char *system_subsystem_prefix,
                                       const char *system,
                                       const char *system_subsystem_separator,
                                       const char *subsystem,
                                       const char *source_file_name,
                                       int source_file_line,
                                       const char *function_prefix,
                                       const char *function_name,
                                       const char *entry_prefix,
                                       const char *entry)
{
    char *heap_string;
    int asprintf_result = pEp_asprintf(& heap_string,
                                       PEP_LOG_PRINTF_FORMAT,
                                       PEP_LOG_PRINTF_ACTUALS);
    if (heap_string == NULL || asprintf_result < 1) {
        free(heap_string);
        return PEP_OUT_OF_MEMORY;
    }

    OutputDebugString(heap_string);
    free(heap_string);
    return PEP_STATUS_OK;
}
#endif /* #if defined (PEP_HAVE_WINDOWS_LOG) */


/* Logging facility: log an entry (function API)
 * ***************************************************************** */

DYNAMIC_API PEP_STATUS pEp_log(PEP_SESSION session,
                               PEP_LOG_LEVEL level,
                               const char *system,
                               const char *subsystem,
                               const char *source_file_name,
                               int source_file_line,
                               const char *function_name,
                               const char *entry)
{
    /* Sanity checks. */
    assert(session);
    if (! session)
        return PEP_ILLEGAL_VALUE;

    /* Before doing anything, check that the log level does not exceed the
       verbosity limit; if it does just return without doing anything. */
    if (level > PEP_LOG_LEVEL_MAXIMUM)
        return PEP_STATUS_OK;

    /* Get the current time. */
    time_t now_in_seconds = time(NULL);
    timestamp* now = new_timestamp(now_in_seconds);
    if (now == NULL)
        return PEP_OUT_OF_MEMORY;

    /* Get the current pid. */
    pid_t pid = getpid();

    /* Normalise system/subsystem strings and compute cosmetic parameters. */
    const char *system_subsystem_prefix = " ";
    const char *system_subsystem_separator = "/";
    if (EMPTYSTR(system) && EMPTYSTR(subsystem))
        system_subsystem_prefix = "";
    if (EMPTYSTR(system)) {
        system = "";
        system_subsystem_separator = "";
    }
    if (EMPTYSTR(subsystem)) {
        subsystem = "";
        system_subsystem_separator = "";
    }

    /* Normalise location strings and compute cosmetic parameters. */
    if (EMPTYSTR(source_file_name))
        source_file_name = "UNKNOWN_FILE";
    const char *function_prefix = ":";
    if (EMPTYSTR(function_name)) {
        function_prefix = "";
        function_name = "";
    }

    /* Normalise entry and compute cosmetic parameters. */
    const char *entry_prefix = " ";
    if (EMPTYSTR(entry)) {
        entry_prefix = "";
        entry = "";
    }

    /* Now prepare for calling helper functions which will perform the actual
       logging, for each destination.  Since these functions have many
       parameters which are always the same, it is convenient to define what the
       actuals are once and for all. */
#define ACTUALS                                                              \
    session, level,                                                          \
    now,                                                                     \
    pid,                                                                     \
    system_subsystem_prefix, system, system_subsystem_separator, subsystem,  \
    source_file_name, source_file_line, function_prefix, function_name,      \
    entry_prefix, entry

    /* Evalutate an expression returning a pEp status; combine its result with
       the current status, updating the current status if the new one is "worse"
       than the current value. */
#define COMBINE_STATUS(expression)                                             \
    do {                                                                       \
        PEP_STATUS _new_status = (expression);                                 \
        /* This assumes, somewhat crudely, that higher-valued error codes      \
           are "more serious".  It is an acceptable approximation in the       \
           sense that non-zero status codes are more serious than              \
           PEP_STATUS_OK ; ranking different kinds of errors seems futile. */  \
        if (_new_status > status)                                              \
            status = _new_status;                                              \
    } while (false)

    /* Now log to each enabled destination, combining the status we obtain for
       every attempt.  Notice that we do not bail out on the first error. */
    PEP_STATUS status = PEP_STATUS_OK;
#if defined (PEP_HAVE_STDOUT_AND_STDERR)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDOUT)
        COMBINE_STATUS(_pEp_log_file_star(stdout, ACTUALS));
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDERR)
        COMBINE_STATUS(_pEp_log_file_star(stderr, ACTUALS));
#endif /* #if defined (PEP_HAVE_STDOUT_AND_STDERR) */

    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_DATABASE)
        ;  // FIXME: implement.

#if defined (PEP_HAVE_SYSLOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_SYSLOG)
        COMBINE_STATUS(_pEp_log_syslog(ACTUALS));
#endif /* #if defined (PEP_HAVE_SYSLOG) */

#if defined (PEP_HAVE_ANDROID_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_ANDROID)
        COMBINE_STATUS(_pEp_log_android_log(ACTUALS));
#endif /* #if defined (PEP_HAVE_ANDROID_LOG) */

#if defined (PEP_HAVE_WINDOWS_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_WINDOWS)
        COMBINE_STATUS(_pEp_log_windows_log(ACTUALS));
#endif /* #if defined (PEP_HAVE_WINDOWS_LOG) */

    free (now);
    return status;
}
