/**
 * @file    debug.h
 * @brief   pEp Engine debugging facilities
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

// (setq show-trailing-whitespace t indicate-empty-lines t)

#ifndef PEP_ENGINE_DEBUG_H
#define PEP_ENGINE_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>  // FIXME: remove unless used
#include <stdio.h>

#include "pEpEngine.h"
#include "pEp_log.h"    /* We log on requirement / assertion failure. */
#include "status_to_string.h" /* for _PEP_LOG_LOCAL_FAILURE_IF_ENABLED */


/* Safety modes
 * ***************************************************************** */

/* The pEp Engine can be configured to follow exactly one of the following
   modes, according to the value of the macro PEP_SAFETY_MODE (see below).
   The Engine safety mode determines defensiveness and fatality (see below)
   for requirements and assertions. */
typedef enum {
    /* This mode is intended for production. */
    PEP_SAFETY_MODE_RELEASE    = 0,

    /* This mode is useful for debugging code which uses the Engine. */
    PEP_SAFETY_MODE_DEBUG      = 1,

    /* This mode is useful for debugging the Engine itself. */
    PEP_SAFETY_MODE_MAINTAINER = 2
} PEP_safety_mode;


/* Configuration
 * ***************************************************************** */

/* If the safety mode has not been defined on the command line use a sensible
   default.
   Notice that PEP_SAFETY_MODE_MAINTAINER is never the default: the few Engine
   developers will set that mode when needed, without inconveniencing the many
   Engine users. */
#if ! defined(PEP_SAFETY_MODE)
#   if defined(NDEBUG)
#       define PEP_SAFETY_MODE  PEP_SAFETY_MODE_RELEASE
#   else
#       define PEP_SAFETY_MODE  PEP_SAFETY_MODE_DEBUG
#   endif
#endif



/* Define defensiveness and fatality mode.
 * ***************************************************************** */

/* FIXME: About this section: I am not even remotely sure that these four
          definitions match what Volker wants; however I think I can satisfy
          any requirement he has by combining their four values. */

/* These constant expressions evaluate to non-false when we check for
   requirements or assertions at all; otherwise assertions and requirements
   will be completely ignored, with the condition not even computed.
   These Boolean values express *defensiveness*. */
#define PEP_CHECK_REQUIREMENTS  \
    true
#define PEP_CHECK_ASSERTIONS  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)

/* These constant expressions evaluate to non-false when failed checks should
   cause an abort.
   These Boolean values express *fatality*. */
#define PEP_ABORT_ON_VIOLATED_REQUIRE  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)
#define PEP_ABORT_ON_VIOLATED_ASSERT  \
    (PEP_SAFETY_MODE >= PEP_SAFETY_MODE_DEBUG)


/* Assertions and requirements
 * ***************************************************************** */

/* Here a "check" is either an assertion or a requirement. */

/* Complain to the log about a violated check. */
#define _PEP_LOG_VIOLATED_CHECK(what_as_string, expression)      \
    PEP_LOG_CRITICAL("p≡p", "Engine",                            \
                     what_as_string " violated: " # expression)

/* Emit a logging entry about the current function being entered, level Function
   -- as long as the feature is enabled via PEP_LOG_FUNCTION_ENTRY . */
#if defined (PEP_LOG_FUNCTION_ENTRY)
#   define _PEP_LOG_FUNCTION_ENTRY_IF_ENABLED                                 \
        PEP_LOG_FUNCTION("p≡p", "Engine",                                     \
                         "Enter" /* no need to repeat the function name. */)
#else
#   define _PEP_LOG_FUNCTION_ENTRY_IF_ENABLED  \
    do { } while (false)
#endif

/* Same idea as LOG_FUNCTION_ENTRY, for local checks.  The argument is the
   expression whose evaluation failed.  Notice that this uses a captured
   variable of type PEP_STATUS named "status". */
#if defined (PEP_LOG_LOCAL_FAILURE)
#   define _PEP_LOG_LOCAL_FAILURE_IF_ENABLED(expression)             \
        PEP_LOG_NONOK("p≡p", "Engine",                               \
                      "%s evaluated to %li %s",                      \
                      # expression,                                  \
                      (long) status, pEp_status_to_string (status))
#else
#   define _PEP_LOG_LOCAL_FAILURE_IF_ENABLED(expression)  \
    do { } while (false)
#endif

/* Perform a chack.  In case of failure log if appropriate according to the kind
   of check, and either execute the given statement or abort, as requested. */
#define _PEP_CHECK_ORELSE(what_as_string, check, abort_on_failure,  \
                          expression, else_statement)               \
    do {                                                            \
        if ((check) && ! (expression)) {                            \
            _PEP_LOG_VIOLATED_CHECK(what_as_string, expression);    \
            if (abort_on_failure)                                   \
                abort();                                            \
            do {                                                    \
                else_statement;                                     \
            } while (false);                                        \
        }                                                           \
    } while (false)

/**
 *  <!--       PEP_ASSERT()       -->
 *
 *  @brief Expand to an assertion on the given expression.  The run-time
 *         behaviour depends on defensiveness and fatality mode.
 *
 *  @param[in]  expression     the expression asserted to be true
 *
 */
#define PEP_ASSERT(expression)                                              \
    _PEP_CHECK_ORELSE("assertion",                                          \
                      PEP_CHECK_ASSERTIONS, PEP_ABORT_ON_VIOLATED_ASSERT,   \
                      /* I cannot protect the expression with parentheses,  \
                         because the expression is stringised with # and    \
                         used for output: it must match the source. */      \
                      expression, {})

/* Expand to a requirement, executing the given statement in case of failure,
   when not aborting. */
#define _PEP_REQUIRE_ORELSE(expression, else_statement)                         \
    do {                                                                        \
        /* This is used at the beginning of more or less every function, so why \
           not getting this log entry for free?  Of course this will not be     \
           enabled in production because of PEP_LOG_LEVEL_MAXIMUM . */          \
        _PEP_LOG_FUNCTION_ENTRY_IF_ENABLED;                                     \
        _PEP_CHECK_ORELSE("requirement",                                        \
                          PEP_CHECK_REQUIREMENTS, PEP_ABORT_ON_VIOLATED_REQUIRE,\
                         /* See comment above*/ expression, else_statement);    \
    } while (false)

/* Expand to a requirement, returning the result of the evaluation of the given
   expression in case of non-aborting failure. */
#define _PEP_REQUIRE_ORELSE_RETURN(expression, else_expression)  \
    _PEP_REQUIRE_ORELSE(/* See comment above*/ expression,       \
                        { return (else_expression); })

/**
 *  <!--       PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE()       -->
 *
 *  @brief Expand to a requirement on the given expression.  In case of
 *         non-aborting failure execute the statement
 *           return PEP_ILLEGAL_VALUE;
 *
 *  @param[in]  expression     the expression required to be true
 *
 */
#define PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE(expression)        \
    _PEP_REQUIRE_ORELSE_RETURN(/* See comment above*/ expression,  \
                              PEP_ILLEGAL_VALUE)

/**
 *  <!--       PEP_REQUIRE_ORELSE_RETURN_NULL()       -->
 *
 *  @brief Expand to a requirement on the given expression.  In case of
 *         non-aborting failure execute the statement
 *           return NULL;
 *
 *  @param[in]  expression     the expression required to be true
 *
 */
#define PEP_REQUIRE_ORELSE_RETURN_NULL(expression)                      \
    _PEP_REQUIRE_ORELSE_RETURN(/* See comment above*/ expression, NULL)

/**
 *  <!--       PEP_REQUIRE()       -->
 *
 *  @brief A convenience short alias for PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE
 *         which is by far the most common use case of requirements.
 */
#define PEP_REQUIRE  \
    PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE


/* Handling status checks and local failure.  [TENTATIVE]
 * ***************************************************************** */

/* This API is tentative.  Volker does not like it and I am not very convinced
   myself.  It will probably go away.  Nobody should use it yet. */

#define _PEP_SET_STATUS_ORELSE(expression, else_statement,  \
                               ...)                         \
    do {                                                    \
        status = (expression);                              \
        if (status != PEP_STATUS_OK) {                      \
            _PEP_LOG_LOCAL_FAILURE_IF_ENABLED(expression);  \
            do {                                            \
                __VA_ARGS__;                                \
            } while (false);                                \
            do {                                            \
                else_statement;                             \
            } while (false);                                \
        }                                                   \
    } while (false)

#define PEP_SET_STATUS_ORELSE_GOTO(expression, label, ...)          \
    _PEP_SET_STATUS_ORELSE(expression, {goto label;}, __VA_ARGS__)

#define PEP_SET_STATUS_ORELSE_GOTO_END(expression, ...)         \
    PEP_SET_STATUS_ORELSE_GOTO(expression, end, __VA_ARGS__)
#define PEP_SET_STATUS_ORELSE_GOTO_ERROR(expression, ...)       \
    PEP_SET_STATUS_ORELSE_GOTO(expression, error, __VA_ARGS__)

#define ORELSE_GOTO        PEP_SET_STATUS_ORELSE_GOTO
#define ORELSE_GOTO_END    PEP_SET_STATUS_ORELSE_GOTO_END
#define ORELSE_GOTO_ERROR  PEP_SET_STATUS_ORELSE_GOTO_ERROR

#define PEP_SET_STATUS_ORELSE_RETURN(expression, else_result, ...)  \
    _PEP_SET_STATUS_ORELSE(expression, {return (else_result);}, __VA_ARGS__)

#ifdef __cplusplus

} /* extern "C" */
#endif

#endif // #ifndef PEP_ENGINE_DEBUG_H
