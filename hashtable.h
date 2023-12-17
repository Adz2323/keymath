#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Node structure for linked list in each bucket
struct ListNode
{
    char *key;
    struct ListNode *next;
};

// Hash table structure
struct HashTable
{
    struct ListNode **buckets;
    int size;
    int count;
};

// Function to create a hash table
struct HashTable *createHashTable(int size);

// Function to insert a key into the hash table
void insert(struct HashTable *table, const char *key);

// Function to search for a key in the hash table
bool search(struct HashTable *table, const char *key);

// Function to delete a key from the hash table
void deleteKey(struct HashTable *table, const char *key);

// Function to destroy the hash table and free memory
void destroyHashTable(struct HashTable *table);

#endif // HASHTABLE_H
