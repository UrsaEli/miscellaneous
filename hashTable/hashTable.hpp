//
// Dan Clark
// dandclark.github.com
//
// hashTable.hpp
//
// Implementation of a simple templated closed-addressing hash table.
//

#include <cassert>
#include <iostream>
#include <list>
#include <string>
#include <vector>

template <typename V>
class HashTable {

    public:

    HashTable();
    HashTable(size_t numBuckets);
    ~HashTable();

    bool hasEntry(std::string key) const;

    void set(std::string key, const V* value); 
    V* get(std::string key) const;

    // Returns true if value was removed, false if key was not present
    // in the table.
    bool remove(std::string key);

    private:

    int getBucketFromKey(std::string key) const; 
    
    struct Entry {
        std::string key;
        const V* value;
    };

    typedef std::list<Entry*> Bucket;
    static const size_t DEFAULT_NUM_BUCKETS;
    size_t numBuckets;
    std::vector<Bucket> buckets;

};

template <typename V>
const size_t HashTable<V>::DEFAULT_NUM_BUCKETS = 1000;

template <typename V>
HashTable<V>::HashTable() : numBuckets(DEFAULT_NUM_BUCKETS),
            buckets(DEFAULT_NUM_BUCKETS) { }

template <typename V>
HashTable<V>::HashTable(size_t numBuckets) : numBuckets(numBuckets),
            buckets(numBuckets) {
    assert(numBuckets > 0);
}

template <typename V>
HashTable<V>::~HashTable() {
    for(typename std::vector<Bucket>::iterator it1 = this->buckets.begin();
            it1 != this->buckets.end(); ++it1) {
        for(typename Bucket::iterator it2 = it1->begin(); it2 != it1->end(); ++it2) {
            delete *it2;
        }
    }
}

template <typename V>
bool HashTable<V>::hasEntry(std::string key) const {
   int bucketIndex = getBucketFromKey(key);

    for(typename Bucket::const_iterator it = this->buckets[bucketIndex].begin();
            it != this->buckets[bucketIndex].end(); ++it) {
        if ((*it)->key == key) {
            return true;
        } 
    }

    return false;
}

template <typename V>
void HashTable<V>::set(std::string key, const V* value) {
   int bucketIndex = getBucketFromKey(key);

    std::cout << "Setting key " << key << " in bucket index " << bucketIndex << std::endl; 

    for(typename Bucket::const_iterator it = this->buckets[bucketIndex].begin();
            it != this->buckets[bucketIndex].end(); ++it) {
        if ((*it)->key == key) {
            (*it)->value = value;
            return;
        } 
    }

    // Didn't find in bucket
    Entry* entry = new Entry();
    entry->key = key;
    entry->value = value;
    this->buckets[bucketIndex].push_back(entry);
}
 
template <typename V>
V* HashTable<V>::get(std::string key) const {
   int bucketIndex = getBucketFromKey(key);

    std::cout << "Getting key " << key << " from bucket index " << bucketIndex << std::endl; 

    for(typename Bucket::const_iterator it = this->buckets[bucketIndex].begin();
            it != this->buckets[bucketIndex].end(); ++it) {
        if ((*it)->key == key) {
            return const_cast<V*>((*it)->value);
        } 
    }

    return NULL;
}

template <typename V>
bool HashTable<V>::remove(std::string key) {
   int bucketIndex = getBucketFromKey(key);

    for(typename Bucket::iterator it = this->buckets[bucketIndex].begin();
            it != this->buckets[bucketIndex].end(); ++it) {
        if ((*it)->key == key) {
            delete *it;
            this->buckets[bucketIndex].erase(it); 
            return true;
        } 
    }

    return false;
}

// Not a particularly robust hash function, but it should get the job done.
template <typename V>
int HashTable<V>::getBucketFromKey(std::string key) const {
    const int largePrime = 65537;
    int keyNum = 1597; // seed with another large prime

    for(std::string::const_iterator it = key.begin(); it != key.end(); it++) {
       keyNum *= static_cast<int>(*it) * largePrime;
    }
    
    return (keyNum % this->numBuckets);
}

