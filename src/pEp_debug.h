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

#include "pEpEngine.h"
#include "pEp_log.h"    /* We log on requirement / assertion failure. */

#include <stdbool.h>
#include <stdio.h>


/* Introduction
 * ***************************************************************** */

//...


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
          definitions match what Volker wants; however I think I can satisfy any
          requirement he has by combining their four values. */

/* These constant expressions evaluate to non-false iff we check for
   requirements or assertions at all; otherwise assertions and requirements
   will be completely ignored, with the condition not even computed.
   These Boolean values express *defensiveness*. */
#define PEP_CHECK_REQUIREMENTS  \
    true
#define PEP_CHECK_ASSERTIONS  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)

/* These constant expressions evaluate to non-false iff a failed check causes
   an abort.
   These Boolean values express *fatality*. */
#define PEP_ABORT_ON_VIOLATED_REQUIRE  \
    (PEP_SAFETY_MODE >= PEP_SAFETY_MODE_DEBUG)
#define PEP_ABORT_ON_VIOLATED_ASSERT  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)


/* Assertions
 * ***************************************************************** */

#define PEP_LOG_VIOLATED_CHECK(what_as_string, expression)       \
    PEP_LOG_CRITICAL("pEpEngine", NULL,                          \
                     what_as_string " violated: " # expression)

#define PEP_CHECK_ORELSE(what_as_string, check, abort_on_failure,  \
                         expression, else_statement)               \
    do {                                                           \
        if ((check) && ! (expression)) {                           \
            PEP_LOG_VIOLATED_CHECK(what_as_string, expression);    \
            if (abort_on_failure)                                  \
                abort();                                           \
            else                                                   \
                do {                                               \
                    else_statement;                                \
                } while (false);                                   \
        }                                                          \
    } while (false)

#define PEP_ASSERT(expression)                                            \
    PEP_CHECK_ORELSE("assertion",                                         \
                     PEP_CHECK_ASSERTIONS, PEP_ABORT_ON_VIOLATED_ASSERT,  \
                     expression, {})
#define PEP_REQUIRE(expression)                                              \
    PEP_CHECK_ORELSE("requirement",                                          \
                     PEP_CHECK_REQUIREMENTS, PEP_ABORT_ON_VIOLATED_REQUIRE,  \
                     expression, {})

#define PEP_REQUIRE_ORELSE_ILLEGAL(expression)                               \
    PEP_CHECK_ORELSE("requirement",                                          \
                     PEP_CHECK_REQUIREMENTS, PEP_ABORT_ON_VIOLATED_REQUIRE,  \
                     /* I cannot protect the expression with parentheses,    \
                        because the expression is stringised with # and      \
                        used for output: it must match the sources. */       \
                     expression, { return PEP_STATUS_ILLEGAL_VALUE; })
#define PEP_REQUIRE_ORELSE_GOTO(expression, label)                           \
    PEP_CHECK_ORELSE("requirement",                                          \
                     PEP_CHECK_REQUIREMENTS, PEP_ABORT_ON_VIOLATED_REQUIRE,  \
                     /* See the comment above. */                            \
                     expression, { goto label; })
// FIXME: Do I need PEP_REQUIRE_ORELSE_GOTO?  If not I can name that PEP_REQUIRE ...


/* Requirements
 * ***************************************************************** */

// REQUIRE uses ASSERT

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // #ifndef PEP_ENGINE_DEBUG_H
