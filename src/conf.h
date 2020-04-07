#if !defined(_cd983b68_dc58_4df6_a1ee_6ccd407934c4)
#define _cd983b68_dc58_4df6_a1ee_6ccd407934c4

#include "hash.h"
#include <stdio.h>

/* Read configuration file.
 *
 * Returns a hashtable of key-value pairs of strings.  
 *
 * These functions read the following configuration from either a FILE object or
 * file a file by name.  
 * 
 * There are three possibilities of options: existential, short key-value, long
 * key-value.  Existential options simply exist in the file.  Short key-value
 * options are keys associated with a one-line value.  Long key-values are keys
 * associated with a multi-line value.  Multi-line, long values are denoted with
 * two less-than characters (<<) and a terminating token.  The token can be any
 * sequence of symbols ignoring spaces.  The value is all of the following lines
 * upto but excluding a line with the termination token on its own.  The
 * number-sign (#) is the comment character in all context except in long
 * key-values.
 *
 * Example (example starts on column 3): 
 *
 * # Enabling Logging
 * LOGGING
 * 
 * # Listening Port 
 * # Note that the port number is a the string "1234". Spaces are ignored. 
 * PORT = 1234
 * 
 * # Message Of The Day
 * MOD << EOF
 * Welcome.
 * Send a zero-byte packet to end a session.
 * EOF
 */
hashtable readconf(char* filename);
hashtable freadconf(FILE* file);


#endif 
