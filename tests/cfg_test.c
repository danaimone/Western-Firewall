#include "check.h"
#include "hash.h"
#include "conf.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STR1(x)  #x
#define STR(x)  STR1(x)

/* This test is to simply test the basic hash table functions 
 *
 */
START_TEST (test_read) {

  hashtable ht = readconf( STR(TESTSDIR) "/test_config");
  ck_assert(ht != NULL);

  ck_assert(hthaskey(ht, "ext1", strlen("ext1")));
  ck_assert(NULL == htfind(ht, "ext1", strlen("ext1")));
  ck_assert(hthasstrkey(ht, "ext2"));
  ck_assert(NULL == htstrfind(ht, "ext2"));
  ck_assert(hthasstrkey(ht, "ext3"));
  ck_assert(NULL == htstrfind(ht, "ext3"));

  ck_assert(NULL != htstrfind(ht, "short1"));
  ck_assert(0 == strcmp("value", htstrfind(ht, "short1")));

  ck_assert(NULL != htstrfind(ht, "short 2"));
  ck_assert(0 == strcmp("value 2", htstrfind(ht, "short 2")));

  ck_assert(NULL != htstrfind(ht, "long1"));
  ck_assert(0 == strcmp("hello\nworld", htstrfind(ht, "long1")));
  

}
END_TEST




Suite* htsuite() {

  Suite* s = suite_create("Config file");
  TCase* t = tcase_create("reading");

  if(s != NULL && t != NULL) {
    tcase_add_test(t, test_read);
    suite_add_tcase(s, t);
  }
  
  return s;
}


int main() {

  Suite*   s = htsuite();

  SRunner* r = srunner_create(s);
  srunner_run_all(r, CK_NORMAL);
  size_t failed = srunner_ntests_failed(r);
  srunner_free(r);

  return (failed == 0
          ? EXIT_SUCCESS
          : EXIT_FAILURE);
}
  
