//
// Dan Clark
// dandclark.github.com
//
// lruCache.java
//
// LRU Cache and basic tests.
// Possible improvements could be the use of a FIFO queue or actual timestamps
// (instead of manually incrementing the clock of each cache line on each access)
// to keep track of the least recently used line.
//

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class TestLRUCache {

    public static void main(String[] args) {
        System.out.println("Testing LRUCache...");

        // Could provide a fully mocked "memory" which tests that all
        // the reads and writes are happening at the right times.
        // However for now I'm just doing manual verification that the
        // right lines are getting kept/flushed at the right times.
        Map<Integer,Integer> fakeMemory = new HashMap<Integer,Integer>();
        LRUCache cache = new LRUCache(3, fakeMemory);

        cache.write(101, 1);
        cache.write(102, 2);
        cache.write(103, 3);
        cache.write(104, 4);
        cache.write(105, 5);
        assert(cache.read(101) == 1);
        assert(cache.read(104) == 4);
        assert(cache.read(101) == 1);
        assert(cache.read(103) == 3);
        assert(cache.read(104) == 4);
        assert(cache.read(105) == 5);
        cache.write(105, 15);
        cache.write(102, 12);
        assert(cache.read(101) == 1);
        cache.write(103, 13);
        cache.write(102, 22);
        assert(cache.read(102) == 22);
        assert(cache.read(105) == 15);
        assert(cache.read(103) == 13);

        System.out.println("Flushing cache...");
        cache.ensureAllLinesFlushed();

        System.out.println("Tests passed");
    }
}

class LRUCache {

    public LRUCache(int numLines, Map<Integer,Integer> memory) {
        this.memory = memory;
        
        this.cacheLines = new ArrayList<CacheLine>(numLines);
        for(int i = 0; i < numLines; ++i) {
            this.cacheLines.add(new CacheLine());
        }
    }

    public int read(int address) {
        System.out.println("*** Reading address " + address + " ***");
        
        Integer value = null;
        for(CacheLine cacheLine : this.cacheLines) {
            ++cacheLine.clock;
            if(cacheLine.isValid && address == cacheLine.address) {
                cacheLine.clock = 0;
                value = cacheLine.value;
            }
        }

        // Address not in cache, go to memory
        if(value == null) {
            CacheLine lruLine = this.cacheLines.get(this.getEmptyOrLeastRecentlyUsedIndex());
            this.ensureLineFlushed(lruLine);           
 
            System.out.println("Reading main memory at address " + address);
            value = this.memory.get(address);

            lruLine.isValid = true;
            lruLine.isDirty = false;
            lruLine.clock = 0;
            lruLine.address = address;
            lruLine.value = value; 
        } 

        System.out.println("Got value " + value);
        return value;
    }

    public void write(int address, int value) {
        System.out.println("*** Writing address " + address + " with value " + value + " ***");
        boolean addressFoundInCache = false;
        for(CacheLine cacheLine : this.cacheLines) {
            ++cacheLine.clock;
            if(cacheLine.isValid && address == cacheLine.address) {
                addressFoundInCache = true;
                cacheLine.clock = 0;
                cacheLine.isDirty = true;
                cacheLine.value = value;
            }
        }

        // Address not in cache, need to replace an existing line
        if(!addressFoundInCache) {
            CacheLine lruLine = this.cacheLines.get(this.getEmptyOrLeastRecentlyUsedIndex());
            this.ensureLineFlushed(lruLine);    
        
            lruLine.isValid = true;
            lruLine.isDirty = true;
            lruLine.clock = 0;
            lruLine.address = address;
            lruLine.value = value; 
        } 
    }

    public void ensureAllLinesFlushed() {
        for(CacheLine cacheLine : this.cacheLines) {
            this.ensureLineFlushed(cacheLine);
        }
    }

    // Write back the value currently in the line if it differs from the one in memory
    private void ensureLineFlushed(CacheLine cacheLine) {
        if(cacheLine.isDirty) {
            System.out.println("Flushing address " + cacheLine.address + " value " +
                    cacheLine.value + " clock " + cacheLine.clock);

            this.memory.put(cacheLine.address, cacheLine.value);
            cacheLine.isDirty = false; 
        }
    }

    private int getEmptyOrLeastRecentlyUsedIndex() {
        int highestClockIndex = 0;
        int highestClockValue = 0;

        for(int i = 0; i < this.cacheLines.size(); ++i) {
            if(!this.cacheLines.get(i).isValid) {
                // Quick out if we find an unused line; we always want to fill those first.
                return i;
            } else if(this.cacheLines.get(i).clock > highestClockValue) {
                highestClockIndex = i;
                highestClockValue = this.cacheLines.get(i).clock;
            }
        }

        return highestClockIndex;
    }
 
    private ArrayList<CacheLine> cacheLines;
    private Map<Integer,Integer> memory; 

    private class CacheLine {
        public boolean isValid;
        public boolean isDirty;
        public int clock;
        public int address;
        public int value;
    }
}
