//
// Dan Clark
// dandclark.github.com
//
// test.cpp
//
// Tests for HashTable class.
//

#include "hashTable.hpp"
#include <cassert>
#include <iostream>

using std::cout;
using std::endl;
using std::string;

void testHashTable(size_t numBuckets);

int main() {

    testHashTable(1);
    testHashTable(2);
    testHashTable(20);
    testHashTable(100);
    testHashTable(1000);
    testHashTable(100000);

    return 0;
}

void testHashTable(size_t numBuckets) {

    cout << "Testing HashTable with " << numBuckets << " buckets..." << endl;

    HashTable<string> table(numBuckets);

    string* bar = new string("bar");
    string* baz = new string("baz");
    string* a = new string("a");
    string* b = new string("b");
    string* c = new string("c");
    string* d = new string("d");
    string* e = new string("e");

    table.set("foo", bar);

    cout << "In table, foo is " << *table.get("foo") << endl;

    assert(table.get("foo") == bar);

    table.set("aa", a);
    table.set("bb", b);
    table.set("cc", c);
    table.set("dd", d);
    table.set("ee", e);

    assert(table.get("aa") == a);
    assert(table.get("bb") == b);
    assert(table.get("cc") == c);
    assert(table.get("dd") == d);
    assert(table.get("ee") == e);

    table.set("foo", baz);
    assert(table.get("foo") == baz);
    assert(table.get("notInTable") == NULL);

    bool removed = table.remove("foo");
    assert(removed && table.get("foo") == NULL); 
    assert(!table.remove("alsoNotInTable"));

    assert(table.hasEntry("aa"));
    assert(table.hasEntry("bb"));
    assert(table.hasEntry("cc"));
    assert(table.hasEntry("dd"));
    assert(table.hasEntry("ee"));
    assert(!table.hasEntry("foo"));
    assert(!table.hasEntry("notInTable"));

    cout << "All tests passed." << endl;

    delete bar;
    delete baz;
    delete a;
    delete b;
    delete c;
    delete d;
    delete e;
}
