/**
 * @file    sql_reliability.c
 * @brief   Internal definitions to make SQLite easy to use safely in
 *          multi-threaded applications, using loops and spinlocks with
 *          exponential backoff.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

/* #define _EXPORT_PEP_ENGINE_DLL */  /* I should uncomment this in case some
                                         function defined here gets exported. */
#include "sql_reliability.h"

#include "pEp_internal.h"

#include "pEpEngine.h"

#include <errno.h>


/* Exponential backoff.
 * ***************************************************************** */

PEP_STATUS pEp_backoff_state_initialize(
   PEP_SESSION session,
   struct pEp_backoff_state *s,
   const char *source_location)
{
    //PEP_REQUIRE(session && s);

    s->failure_no = 0;
    s->total_time_slept_in_ms = 0;
    s->current_upper_limit_in_ms = PEP_INITIAL_UPPER_LIMIT_BACKOFF_IN_MS;
    s->source_location = source_location;
    return PEP_STATUS_OK;
}

PEP_STATUS pEp_backoff_state_finalize(
   PEP_SESSION session,
   const struct pEp_backoff_state *s)
{
    //PEP_REQUIRE(session && s);

    /* I might want to actually add some statistics in the session, in the
       future. */
    if (s->failure_no > 0)
        LOG_NONOK("SQLite at %s: success after %i failures, total backoff %li ms",
                  s->source_location,
                  (int) s->failure_no, (long) s->total_time_slept_in_ms);
    return PEP_STATUS_OK;
}

/* Increase the backoff length and the failure counter in the pointed state,
   recording that we have just slept for the given amount of time. */
static void pEp_backoff_bump(struct pEp_backoff_state *s,
                             long sleep_time_ms)
{
    /* Record statistics. */
    s->failure_no ++;
    s->total_time_slept_in_ms += sleep_time_ms;

    /* Raise the sleep time upper limit. */
    double unclamped_upper_limit
        = (s->current_upper_limit_in_ms * PEP_BACKOFF_UPPER_LIMIT_GROWTH_FACTOR);
    if (unclamped_upper_limit <= PEP_MAXIMUM_BACKOFF_IN_MS)
        s->current_upper_limit_in_ms = unclamped_upper_limit;
    else
        s->current_upper_limit_in_ms = PEP_MAXIMUM_BACKOFF_IN_MS;
}

/* Return a random sleeping time appropriate for the current state, without
   bumping it. */
static long pEp_backoff_compute_sleep_time(
   PEP_SESSION session,
   const struct pEp_backoff_state *s)
{
    //PEP_REQUIRE(session && s);

    long range_width
        = (s->current_upper_limit_in_ms - PEP_MINIMUM_BACKOFF_IN_MS);
    assert(range_width >= 0);
    long random_component = rand() % (range_width + 1);
    return PEP_MINIMUM_BACKOFF_IN_MS + random_component;
}

PEP_STATUS pEp_back_off(PEP_SESSION session,
                        struct pEp_backoff_state *s)
{
    //PEP_REQUIRE(session && s);

    /* Very easy: sleep, and bump. */
    long sleep_time_in_ms = pEp_backoff_compute_sleep_time(session, s);
    //LOG_NONOK("backing off for %li ms", sleep_time_in_ms);
    pEp_sleep_ms(sleep_time_in_ms);
    pEp_backoff_bump(s, sleep_time_in_ms);

    return PEP_STATUS_OK;
}


/* Convenience wrapper for "automatic" one-statement transactions
 * ***************************************************************** */

int pEp_sqlite3_step_nonbusy(PEP_SESSION session,
                             sqlite3_stmt *prepared_statement)
{
    PEP_REQUIRE_ORELSE_RETURN(session && prepared_statement,
                              /* Something generic: this will not happen anyway
                                 except for internal bugs */ SQLITE_ERROR);
    int sqlite_status;

    PEP_SQL_BEGIN_LOOP(sqlite_status);
    sqlite_status = sqlite3_step(prepared_statement);
    PEP_SQL_END_LOOP();

    return sqlite_status;
}
