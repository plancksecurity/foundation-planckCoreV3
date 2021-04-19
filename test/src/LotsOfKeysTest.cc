// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>
#include <sys/time.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include "pEpEngine.h"
#include "pEp_internal.h"

#include "test_util.h"
#include "TestConstants.h"

#include "Engine.h"

#include <gtest/gtest.h>


// Whether to log to the file system (in /tmp).
#define LOG 0
// How to plot (in R).  You need to enable LOG above.
#if 0

library(ggplot2);

t = "2019XXXX-XXXXXX";
find_keys = read.csv(sprintf("/tmp/pep-benchmark-find-keys-%s.csv", t),
                     header=T, sep=",")
get_ids = read.csv(sprintf("/tmp/pep-benchmark-get-identity-%s.csv", t),
                   header=T, sep=",")
ggplot(find_keys, aes(x=Keys, y=run0_us_per_op), tag="FOO") +
    geom_point() +
    geom_point(data = get_ids, aes(Keys, run0_us_per_op), colour = 'red') +
    scale_x_log10() + guides(fill = guide_legend()) +
    labs(title="Microseconds/Op for a Key/Management DB with x keys",
         x="Keys in DB", y="usec")

ggsave("/tmp/pep-benchmark.pdf", width = 4, height = 4)
#endif

// Only really run the bench mark if logging is enabled.
#if LOG > 0
// Maximum number of keys.
#  define N 31622
// Amount of time to run each benchmark, in usecs.
#  define TIME 2 * 1000000
#else
// Don't actually run the benchmark.
#  define N 3
#  define TIME 0
#endif

// Number of times to run each benchmark.
#define REPITIONS 3

// 10^x, x=0.5.. step 0.5.
const int _exp[] = { 3, 10, 31, 100, 316, 1000, 3162, 10000, 31622,
                    100000, 316227, 1000000, 3162277, 10000000,
                    31622776, 100000000, 316227766, 1000000000 };
#define BENCHMARKS (sizeof(_exp) / sizeof(_exp[0]))

struct stats {
    FILE *fp;
    const char *name;
    struct {
        // Number of keys in the db.
        int keys;
        unsigned long long time[REPITIONS];
        unsigned long long ops[REPITIONS];
    } benchmarks[BENCHMARKS];
};

struct stats *stats_new(const char *name)
{
    struct stats *stats = (struct stats *) calloc(1, sizeof(*stats));
    stats->name = name;
    return stats;
}

unsigned long long time() {
    struct timeval tv;
    int err = gettimeofday(&tv, NULL);
    assert(err == 0);

    return (unsigned long long) (tv.tv_sec * 1000000 + tv.tv_usec);
}

static char start_time[100];

static void dump_stats(struct stats *stats, int benchmark) {
    if (LOG && ! stats->fp) {
        char fn[1024];
        sprintf(fn, "/tmp/pep-benchmark-%s-%s.csv", stats->name, start_time);
        stats->fp = fopen(fn , "w");
        if (! stats->fp) {
            printf("Opening %s failed.\n", fn);
            abort();
        }

        fprintf(stats->fp, "Keys");
        for (int iter = 0; iter < REPITIONS; iter ++) {
            fprintf(stats->fp, ", run%d_us_per_op, run%d_ops_per_sec", iter, iter);
        }
        fprintf(stats->fp, "\n");
    }

    printf("%-8d keys", stats->benchmarks[benchmark].keys);
    if (stats->fp)
        fprintf(stats->fp, "%d", stats->benchmarks[benchmark].keys);

    for (int iter = 0; iter < REPITIONS; iter ++) {
        double us_per_lookup = (double) stats->benchmarks[benchmark].time[iter]
            / (double) stats->benchmarks[benchmark].ops[iter];
        double ops_per_second = (double) stats->benchmarks[benchmark].ops[iter]
            / ((double) stats->benchmarks[benchmark].time[iter] / 1000000);

        printf("\t%.02f us/op (%.1f ops/s)", us_per_lookup, ops_per_second);
        if (stats->fp)
            fprintf(stats->fp, ", %f, %f", us_per_lookup, ops_per_second);
    }

    printf("\n");
    if (stats->fp) {
        fprintf(stats->fp, "\n");
        fflush(stats->fp);
    }
}

namespace {

	//The fixture for LotsOfKeysTest
    class LotsOfKeysTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            LotsOfKeysTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~LotsOfKeysTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NOTNULL(engine);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NOTNULL(engine->session);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the LotsOfKeysTest suite.

    };

}  // namespace


TEST_F(LotsOfKeysTest, check) {
#ifndef USE_GPG // Our gnupg implementation only accepts the default cipher suite right now    
    struct tm tm;
    time_t t = time((time_t *) NULL);
    localtime_r(&t, &tm);
    strftime(start_time, sizeof(start_time), "%Y%m%d-%H%M%S", &tm);

    struct stats *find_keys_stats = stats_new("find-keys");
    struct stats *get_identity_stats = stats_new("get-identity");

    int benchmark = 0;
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity **ids = (pEp_identity **) calloc(N, sizeof(*ids));
    assert(ids);

    status = config_cipher_suite(session, PEP_CIPHER_SUITE_CV25519);
    PEP_STATUS expected_value = PEP_STATUS_OK;
    ASSERT_OK;

    for (int key = 0; key < N; key ++) {
        // Create key
        char email[1024];
        sprintf(email, "%09d@example.org", key);

        ids[key] = new_identity(strdup(email), NULL, NULL, "Test User");
        status = update_identity(session, ids[key]);
        ASSERT_OK;

        if (key == 0) {
            printf("\nRaw identity:\n");
            printf("   address = %s\n", ids[0]->address);
            printf("       fpr = %s\n", ids[0]->fpr);
            printf("   user_id = %s\n", ids[0]->user_id);
            printf("  username = %s\n", ids[0]->username);
        }

        status = generate_keypair(session, ids[key]);
        ASSERT_OK;

        if (key == 0) {
            printf("\nAfter generating a key:\n");
            printf("   address = %s\n", ids[0]->address);
            printf("       fpr = %s\n", ids[0]->fpr);
            printf("   user_id = %s\n", ids[0]->user_id);
            printf("  username = %s\n", ids[0]->username);
        }

        status = set_identity(session, ids[key]);
        ASSERT_OK;

        if (key == 0) {
            printf("\nSetting identity:\n");
            printf("   address = %s\n", ids[0]->address);
            printf("       fpr = %s\n", ids[0]->fpr);
            printf("   user_id = %s\n", ids[0]->user_id);
            printf("  username = %s\n", ids[0]->username);
        }

        bool do_benchmark = false;
        for (int i = 0; i < sizeof(_exp) / sizeof(_exp[0]); i ++) {
            if (key + 1 == _exp[i]) {
                do_benchmark = true;
            } else if (key + 1 < _exp[i]) {
                break;
            }
        }

        if (! do_benchmark)
            continue;


        // Look up a random key by its email address.
        //
        // This doesn't use the engine, only the pgp
        // implementation.  For Sequoia, this should run in O(log
        // N).
        find_keys_stats->benchmarks[benchmark].keys = key + 1;
        for (int iter = 0; iter < REPITIONS; iter ++) {
            unsigned long long start = time();
            unsigned long long elapsed;
            int ops = 0;

            do {
                int i = random() % (key + 1);
                assert(i <= key);

                stringlist_t* keylist = NULL;
                status = find_keys(session, ids[i]->address, &keylist);
                free_stringlist(keylist);
                ASSERT_EQ(status, PEP_STATUS_OK);
                ops ++;
                elapsed = time() - start;
            } while (elapsed < TIME);

            find_keys_stats->benchmarks[benchmark].ops[iter] = ops;
            find_keys_stats->benchmarks[benchmark].time[iter] = elapsed;
        }

        dump_stats(find_keys_stats, benchmark);


        // Look up a random key by its pep user id.
        //
        // This uses the engine's management databank and doesn't
        // touch the pgp engine's DB.
        get_identity_stats->benchmarks[benchmark].keys = key + 1;
        for (int iter = 0; iter < REPITIONS; iter ++) {
            unsigned long long start = time();
            unsigned long long elapsed;
            int ops = 0;

            do {
                int i = random() % (key + 1);
                pEp_identity *id = NULL;
                status = get_identity(session, ids[i]->address,
                                      ids[i]->user_id, &id);
                ASSERT_EQ(status, PEP_STATUS_OK);
                ASSERT_NOTNULL(id->fpr);
                ASSERT_STREQ(ids[i]->fpr, id->fpr);
                free_identity(id);

                ops ++;
                elapsed = time() - start;
            } while (elapsed < TIME);

            get_identity_stats->benchmarks[benchmark].ops[iter] = ops;
            get_identity_stats->benchmarks[benchmark].time[iter] = elapsed;
        }

        dump_stats(get_identity_stats, benchmark);


        benchmark++;
    }
#endif    
}
