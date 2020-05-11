#include "check.h"
#include "hash.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This test is to simply test the basic hash table functions 
 *
 */
START_TEST (test_insert) {
  hashtable ht = htnew(0, (keycomp)strcmp, NULL);
  
  ck_assert(htinsert(ht, "World", 6, "World"));
  ck_assert_str_eq(htfind(ht, "World", 6), "World");
  ck_assert(hthaskey(ht, "World", 6));
  ck_assert(!hthaskey(ht, "WORLD", 6));
  
  htfree(ht);
}
END_TEST

static
size_t words;

static
char* getword(FILE* file) {
  char*  word = NULL;
  size_t size = 0;

  ssize_t len = getline(&word, &size, file);
  
  if(word != NULL)
    words++;
  
  if(len > 0 && word[len] == '\n') {
    word[len] = '\0';
    len = len - 1;
  }
  
  if(len <= 0 && word != NULL) {
    free(word);
    word = NULL;
    words--;
  }
  
  return word;
}

static
void freeword(void* key, void* same) {
  words--;
  free(key);
}


START_TEST (test_dictionary) {
  FILE*     f  = fopen("/usr/share/dict/words", "r");
  hashtable ht = htnew(0, (keycomp)strcmp, freeword);

  char* word = getword(f);
  while(word != NULL) {
    ck_assert(htinsert(ht, word, strlen(word), word));
    word = getword(f);
  }


  f = freopen("/usr/share/dict/words", "r", f);
  word = getword(f);
  while(word != NULL) {
    ck_assert_str_eq(htfind(ht, word, strlen(word)), word);
    freeword(word, word);
    word = getword(f);    
  }

  fclose(f);
  htfree(ht);

  ck_assert(words == 0);
  
}
END_TEST

START_TEST (test_one_start) {
    hashtable ht = htnew(1, (keycomp)strcmp, NULL);
  
  ck_assert(htinsert(ht, "World", 6, "World"));
  ck_assert_str_eq(htfind(ht, "World", 6), "World");
  ck_assert(hthaskey(ht, "World", 6));
  ck_assert(!hthaskey(ht, "WORLD", 6));
  
  htfree(ht);
}
END_TEST

START_TEST (test_remove) {
  FILE*     f  = fopen("/usr/share/dict/words", "r");
  hashtable ht = htnew(0, (keycomp)strcmp, freeword);

  char* word = getword(f);
  while(word != NULL) {
    ck_assert(htinsert(ht, word, strlen(word), word));
    word = getword(f);
  }

  f = freopen("/usr/share/dict/words", "r", f);
  word = getword(f);
  while(word != NULL) {
    htstrremove(ht, word);
    ck_assert(NULL == htstrfind(ht, word));
    word = getword(f);    
  }

  size_t size = *(size_t*)(ht);
  f = freopen("/usr/share/dict/words", "r", f);
  word = getword(f);    
  while(word != NULL) {
    ck_assert(htinsert(ht, word, strlen(word), word));
    word = getword(f);    
  }

  ck_assert(size == *(size_t*)(ht));

  fclose(f);
  htfree(ht);
}
END_TEST


START_TEST (test_zero_find) {
  hashtable ht = htnew(0, (keycomp)strcmp, NULL);
  
  ck_assert(NULL == htfind(ht, "World", 6));
  
  htfree(ht);
}
END_TEST

Suite* htsuite() {

  Suite* s = suite_create("Hash Table");
  TCase* t = tcase_create("Insert");

  if(s != NULL && t != NULL) {
    tcase_set_timeout(t, 60.0);
    tcase_add_test(t, test_insert);
    tcase_add_test(t, test_dictionary);
    tcase_add_test(t, test_one_start);
    tcase_add_test(t, test_zero_find);
    tcase_add_test(t, test_remove);
    suite_add_tcase(s, t);
  }
  
  return s;
}


int main() {

  Suite*   s = htsuite();

  SRunner* r = srunner_create(s);
  srunner_set_fork_status(r, CK_NOFORK);
  srunner_run_all(r, CK_NORMAL);
  size_t failed = srunner_ntests_failed(r);
  srunner_free(r);

  return (failed == 0
          ? EXIT_SUCCESS
          : EXIT_FAILURE);
}
  
