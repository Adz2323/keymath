#include "hashtable.h"

// Hash function to convert a string key into an array index
unsigned int hashFunction(const char *key, int tableSize) {
    unsigned long hash = 5381;
    int c;

    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash % tableSize;
}

// Create a hash table
struct HashTable *createHashTable(int size) {
    struct HashTable *table = malloc(sizeof(struct HashTable));
    table->size = size;
    table->count = 0;
    table->buckets = malloc(sizeof(struct ListNode*) * size);

    for (int i = 0; i < size; i++) {
        table->buckets[i] = NULL;
    }

    return table;
}

// Insert a key into the hash table
void insert(struct HashTable *table, const char *key) {
    int index = hashFunction(key, table->size);
    struct ListNode *newNode = malloc(sizeof(struct ListNode));
    newNode->key = strdup(key); // Duplicate the key for storage
    newNode->next = table->buckets[index];
    table->buckets[index] = newNode;
    table->count++;
}

// Search for a key in the hash table
bool search(struct HashTable *table, const char *key) {
    int index = hashFunction(key, table->size);
    struct ListNode *list = table->buckets[index];

    while (list != NULL) {
        if (strcmp(list->key, key) == 0) {
            return true;
        }
        list = list->next;
    }

    return false;
}

// Delete a key from the hash table
void deleteKey(struct HashTable *table, const char *key) {
    int index = hashFunction(key, table->size);
    struct ListNode *list = table->buckets[index];
    struct ListNode *prev = NULL;

    while (list != NULL) {
        if (strcmp(list->key, key) == 0) {
            if (prev != NULL) {
                prev->next = list->next;
            } else {
                table->buckets[index] = list->next;
            }
            free(list->key);
            free(list);
            table->count--;
            return;
        }
        prev = list;
        list = list->next;
    }
}

// Destroy the hash table and free memory
void destroyHashTable(struct HashTable *table) {
    for (int i = 0; i < table->size; i++) {
        struct ListNode *list = table->buckets[i];
        while (list != NULL) {
            struct ListNode *temp = list;
            list = list->next;
            free(temp->key);
            free(temp);
        }
    }
    free(table->buckets);
    free(table);
}
