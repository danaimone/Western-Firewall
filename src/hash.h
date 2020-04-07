#if !defined(_62e8cf8e_23ff_416f_b74c_2fae3d075bd9)
#define _62e8cf8e_23ff_416f_b74c_2fae3d075bd9

#include <unistd.h>
#include <stdbool.h>


typedef struct ht_st *hashtable;

/* Generic Key Comparison
 * Returns a negative value if l < r, a positive value if l > r and zero if 
 * l == r. 
 */
typedef int (*keycomp)(void* left, void* right);

/* Generic key/value free
 * When the hash table frees buckets, this function is called to perform any
 * necessary frees on the key or value memory.
 */
typedef void (*keyvalfree)(void* key, void* value);

/* Create a new hash table.
 * 
 *
 */
hashtable htnew (size_t size, keycomp comp, keyvalfree kvfree);

/* Destroy a hash table
 * Frees all of the memory associated with this hash table.  
 */
void htfree(hashtable ht);


/* Insert a new value into the hastable
 * returns true upon success
 *
 */
bool htinsert(hashtable ht, void* key, size_t keysz, void* value);
bool htstrinsert(hashtable ht, char* key, void* value);

/* Find a key
 * returns the value associated with the specified key or NULL if the key is not
 * in the hash table
 */
void* htfind(hashtable ht, void* key, size_t keysz);
void* htstrfind(hashtable ht, char* key);

/* Has Key
 * returns true if the key is in the hashtable.  
 */
bool hthaskey(hashtable ht, void* key, size_t keysz);
bool hthasstrkey(hashtable ht, char* key);


#endif 
