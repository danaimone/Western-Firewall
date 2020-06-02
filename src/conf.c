#include "conf.h"
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

/* Regular Expressions
 *
 * Each regular expression identifies on of the four kinds of lines.  Note that
 * long options break out of the typical matching process.  
 */
static regex_t EXT;
static const char* reEXT =
  "^[[:space:]]*([^[:space:]=<#][^=<#]*[^[:space:]=<#])"
  "[[:space:]]*(#.*)?$";

static regex_t SHORT;
static const char* reSHORT =
  "^[[:space:]]*([^[:space:]=<#][^=<#]*[^[:space:]=<#])"
  "[[:space:]]*=[[:space:]]*"
  "([^[:space:]=<#][^=<#]*[^[:space:]=<#])"
  "[[:space:]]*(#.*)?$";

static regex_t LONG;
static const char* reLONG =
  "^[[:space:]]*([^[:space:]=<#][^=<#]*[^[:space:]=<#])"
  "[[:space:]]*<<[[:space:]]*"
  "([^[:space:]=<#][^=<#]*[^[:space:]=<#])"
  "[[:space:]]*(#.*)?$";

static regex_t COMMENT;
static const char* reCOMMENT =
  "^[[:space:]]*(#.*)?$";

/* Compile the regular expressions.
 *
 * Note that this is an idempotent function.  The static variable beencompiled
 * is set the first time this function is called.  Subsequent calls do no
 * action.  
 */
static
void compregex() {
  static bool beencompiled = false;
  if(!beencompiled) {
    
    int er = regcomp(&EXT, reEXT, REG_EXTENDED);
    if(er != 0) {
      fprintf(stderr, "regcomp(%s) = %d\n", reEXT, er);
      exit(1);
    }

    er = regcomp(&SHORT, reSHORT, REG_EXTENDED);
    if(er != 0) {
      fprintf(stderr, "regcomp(%s) = %d\n", reSHORT, er);
      exit(1);
    }

    er = regcomp(&LONG, reLONG, REG_EXTENDED);
    if(er != 0) {
      fprintf(stderr, "regcomp(%s) = %d\n", reLONG, er);
      exit(1);
    }

    er = regcomp(&COMMENT, reCOMMENT, REG_EXTENDED);
    if(er != 0) {
      fprintf(stderr, "regcomp(%s) = %d\n", reCOMMENT, er);
      exit(1);
    }
    beencompiled = true;
  }
}

/* Key Value free 
 *
 * Memory management for the hash table buckets.  
 */
static
void kvfree(void* key, void* value) {
  free(key);
  free(value);
}


/* Get Input
 * 
 */
static
ssize_t getinput(char** line, size_t* size, FILE* file) {
  assert(line != NULL && size != NULL);

  ssize_t len = getline(line, size, file);
  if(len > 0 && (*line)[len-1] == '\n') {
    (*line)[len-1] = '\0';
    --len;
  }

  return len;
}


/* Read Config
 * filename   The path to a configuration file.
 * returns    a hash table with the key-values from the configuration file
 *
 * This is really just a helper function for freadconf (below).
 */
hashtable readconf(char* filename) {
  assert(filename != NULL);

  hashtable ht = NULL;

  FILE* file = fopen(filename, "r");
  if(file != NULL) {
    ht = freadconf(file);
    fclose(file);
  }
  
  return ht;
}

/* Classify 
 * line   The line to parse and classify
 * key    [out] a newly allocated the key token 
 *
 * This function 
 */

typedef enum {IGNORE, STORE, RDMULTI, ERROR} action;

static
action classify (char* line, char** key, char** value) {
  assert(line  != NULL);
  assert(key   != NULL);
  assert(value != NULL);
  
  action act = IGNORE;
  *key       = NULL;
  *value     = NULL;

  regmatch_t pmatch[3];

  if(0 == regexec(&EXT, line, 3, pmatch, 0)) {
    act    = STORE;
    *key   = strndup(&line[pmatch[1].rm_so], pmatch[1].rm_eo - pmatch[1].rm_so);
  }

  else if(0 == regexec(&SHORT, line, 3, pmatch, 0)) {
    act    = STORE;
    *key   = strndup(&line[pmatch[1].rm_so], pmatch[1].rm_eo - pmatch[1].rm_so);
    *value = strndup(&line[pmatch[2].rm_so], pmatch[2].rm_eo - pmatch[2].rm_so);
  }

  else if(0 == regexec(&LONG, line, 3, pmatch, 0)) {
    act    = RDMULTI;
    *key   = strndup(&line[pmatch[1].rm_so], pmatch[1].rm_eo - pmatch[1].rm_so);
    *value = strndup(&line[pmatch[2].rm_so], pmatch[2].rm_eo - pmatch[2].rm_so);
  }
  else if(0 != regexec(&COMMENT, line, 3, pmatch, 0)) {
    act = ERROR;
  }
  return act;
}

/* append
 * dest   [in/out] the src and destination of the start of the string.
 * src    [in] the rest of the string
 *
 * This function appends src to dest with a new-line in between.  It allocates
 * enough memory for the new string and frees the memory originally pointed at
 * by dest. 
 *
 */
static
void append(char** dest, char* src) {
  assert(dest != NULL);
  if(*dest == NULL) {
    *dest = strdup(src);
  }
  else {
    char* nstr = malloc(2 + strlen(*dest) + strlen(src));
    strcpy(nstr, *dest);
    strcat(nstr, "\n");
    strcat(nstr, src);
    free(*dest);
    *dest = nstr;
  }
}


/* f read config
 * file     The file stream to parse
 * returns  A hash table containing the key-value pairs in file.  
 *
 * This file is in one of two modes: single-line and multi-line.  The string
 * longend is used to determine which state it is in.  Initially the function
 * parses one line at a time.  When the start of a multi-line value is parsed,
 * it switch to multi-line mode.  In multi-line mode, lines are appended
 * together until the end-of-value string is read on a line by itself.  
 */
hashtable freadconf(FILE* file) {
  assert(file != NULL);
  compregex();
  
  hashtable ht   = htnew(32, (keycomp)strcmp, kvfree);

  size_t     errct = 0;
  
  char* longend   = NULL;
  char* longkey   = NULL;
  char* longvalue = NULL;

  char*     line = NULL;
  size_t    size = 0;
  size_t    lno  = 1;
  ssize_t   len  = getinput(&line, &size, file);
  while(len >= 0) {
    
    if(longend == NULL) {
      char* key;
      char* value;
      switch(classify(line, &key, &value)) {

      case STORE:
        htstrinsert(ht, key, value);
        break;
        
      case RDMULTI:
        longend   = value;
        longkey   = key;
        longvalue = NULL;
        break;

      case ERROR:
        fprintf(stderr, "conf error line %lu\n", lno);
        errct = errct + 1;
        break;

      case IGNORE:
        break;
      }
    }
    
    else {
      if(strcmp(longend, line) != 0) {
        append(&longvalue, line);
      }
      else {
        htinsert(ht, longkey, strlen(longkey), longvalue);
        free(longend);
        longend   = NULL;
        longkey   = NULL;
        longvalue = NULL;
      }
    }

    lno  = lno + 1;
    len  = getinput(&line, &size, file);
  }
  
  if(errct > 0) {
    htfree(ht);
    ht = NULL;
  }
  
  return ht;
}
