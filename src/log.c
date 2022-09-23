/**
 * @file    log.c
 * @brief   pEp logging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#define _EXPORT_PEP_ENGINE_DLL
#include "log.h"

#include "pEp_internal.h"
//#include "stringpair.h" // for stringpair_list_t
#include "timestamp.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>


/* Initialisation and finalisation
 * ***************************************************************** */

PEP_STATUS pep_log_initialize(PEP_SESSION session)
{
    return PEP_STATUS_OK;
}

PEP_STATUS pep_log_finalize(PEP_SESSION session)
{
    return PEP_STATUS_OK;
}


/* Logging facility: internal functions
 * ***************************************************************** */

/* We can rely on vsnprintf , which is standard, for implementing vasprintf . */
static int _pEp_vasprintf(char **string_pointer, const char *template,
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
          have its result value which is the required stribg size (minus one
          character for the trailing '\0');
       2. allocate a string with the right size;
       3. all vsnprintf once more, filling the string. */

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

int _pEp_asprintf(char **string_pointer, const char *template, ...)
{
    /* This is a simple wrapper around _pEp_vasprintf, which does the actual
       job. */
    va_list ap;
    va_start(ap, template);
    int res = _pEp_vasprintf(string_pointer, template, ap);
    va_end(ap);
    return res;
}


/* Logging facility: log an entry (function API)
 * ***************************************************************** */

/* Given a log level return its printed representation */
static const char* _log_level_to_string(PEP_LOG_LEVEL level)
{
    switch (level) {
    case PEP_LOG_LEVEL_NOTHING:     return "nothing";
    case PEP_LOG_LEVEL_CRITICAL:    return "CRITICAL";
    case PEP_LOG_LEVEL_ERROR:       return "Error";
    case PEP_LOG_LEVEL_WARNING:     return "Warning";
    case PEP_LOG_LEVEL_EVENT:       return "Event";
    case PEP_LOG_LEVEL_API:         return "API";
    case PEP_LOG_LEVEL_DEBUG:       return "Debug";
    case PEP_LOG_LEVEL_TRACE:       return "Trace";
    case PEP_LOG_LEVEL_EVERYTHING:  return "everything";
    default:                        return "invalid log level";
    }
}

/* The implementation of _pEp_log for FILE * output. */
static PEP_STATUS _pEp_log_file_star(FILE* file_star,
                                     PEP_SESSION session,
                                     PEP_LOG_LEVEL level,
                                     const timestamp *time,
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
    int fprintf_result
        = fprintf(file_star,
                  "%04i-%02i-%02i %02i:%02i:%02i" /* date, time */
                  "%s%s%s%s"                      /* system, subsystem */
                  " %s"                           /* log level */
                  " %s:%i%s%s"                    /* source location */
                  "%s%s"                          /* entry */
                  "\n",
                  time->tm_year + 1900, time->tm_mon + 1, time->tm_mday,
                  time->tm_hour, time->tm_min, time->tm_sec,
                  system_subsystem_prefix, system, system_subsystem_separator,
                      subsystem,
                  _log_level_to_string(level),
                  source_file_name, source_file_line, function_prefix,
                      function_name,
                  entry_prefix, entry);
    if (fprintf_result < 0)
        return PEP_UNKNOWN_ERROR;
    else
        return PEP_STATUS_OK;
}

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
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDOUT)
        COMBINE_STATUS(_pEp_log_file_star(stdout, ACTUALS));
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDERR)
        COMBINE_STATUS(_pEp_log_file_star(stderr, ACTUALS));
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_SYSLOG)
        ;  // FIXME: implement.
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_ANDROID)
        ;  // FIXME: implement.
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_DATABASE)
        ;  // FIXME: implement.

    free (now);
    return status;
}
