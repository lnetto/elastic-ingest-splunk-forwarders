package co.elastic.s2shttp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemoryGuardTests {

    @Test
    void aBatchAloneAlwaysGetsIn() {
        MemoryGuard g = new MemoryGuard(null, 100);
        try (MemoryGuard.Reservation r = g.reserve()) {
            assertTrue(r.resize(1_000), "the only request in flight is never refused");
        }
        assertEquals(0, g.reserved());
    }

    @Test
    void batchesTogetherStayWithinTheBudget() {
        MemoryGuard g = new MemoryGuard(null, 100);
        MemoryGuard.Reservation a = g.reserve();
        MemoryGuard.Reservation b = g.reserve();
        assertTrue(a.resize(60));
        assertFalse(b.resize(60), "over budget while another batch holds memory: busy");
        assertEquals(60, g.reserved());
        assertTrue(b.resize(40));
        assertTrue(a.resize(10), "shrinking always works");
        a.close();
        a.close(); // released once
        assertEquals(40, g.reserved());
        assertTrue(b.resize(1_000), "alone again");
        b.close();
        assertEquals(0, g.reserved());
    }

    /**
     * A body of short lines takes far more heap than its size (about 234 bytes per 2-byte line): the
     * reservation grows with every event made, and a request it can't cover is answered busy.
     */
    @Test
    void tinyEventsAreCountedNotJustBytes() {
        byte[] body = new S2SBodies().meta(0).events(200, "a\n".repeat(5_000)).body(); // 1 million events in 2 MB
        S2SService svc = new S2SService(org.elasticsearch.common.settings.Settings.EMPTY, null, null);
        MemoryGuard g = new MemoryGuard(null, 64L * 1024 * 1024);
        try (MemoryGuard.Reservation other = g.reserve(); MemoryGuard.Reservation r = g.reserve()) {
            assertTrue(other.resize(1)); // another request in flight: the budget applies
            assertEquals(null, svc.decode(new org.elasticsearch.common.bytes.BytesArray(body), "r", null, Map.of(), r), "busy");
            assertTrue(g.reserved() <= 64L * 1024 * 1024);
        }
        assertEquals(0, g.reserved());
        // within budget it is decoded, and what it holds is reserved
        try (MemoryGuard.Reservation r = new MemoryGuard(null, 1L << 40).reserve()) {
            byte[] small = new S2SBodies().meta(0).events(10, "a\n".repeat(100)).body();
            assertEquals(1_000, svc.decode(new org.elasticsearch.common.bytes.BytesArray(small), "r", null, Map.of(), r).size());
        }
    }

    /** A count from the wire never sizes an allocation beyond the bytes that are there (it would stop the node). */
    @Test
    void hugeHeaderCountIsABadBodyNotAnAllocation() {
        byte[] inflated = new S2SBodies().meta(Integer.MAX_VALUE).inflated();
        S2SDecoder.S2SFormatException e = org.junit.jupiter.api.Assertions.assertThrows(S2SDecoder.S2SFormatException.class,
            () -> S2SDecoder.decodeInflated(inflated, bytes -> true));
        assertTrue(e.getMessage().contains("count"), e.getMessage());
    }

    @Test
    void slicesHaveAtMostSliceDocsAndAboutSliceBytes() {
        List<EventAssembler.Doc> docs = new ArrayList<>();
        for (int i = 0; i < 5_000; i++) {
            docs.add(new EventAssembler.Doc("h", "s", "st", "main", null, 0L, null, "x".repeat(10), Map.of(), "r", null, null, 0, 1, null, null));
        }
        assertEquals(S2SIndexer.SLICE_DOCS, S2SIndexer.sliceEnd(docs, 0));
        assertEquals(5_000, S2SIndexer.sliceEnd(docs, 4_000));
        String big = "y".repeat(5 * 1024 * 1024);
        List<EventAssembler.Doc> large = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            large.add(new EventAssembler.Doc("h", "s", "st", "main", null, 0L, null, big, Map.of(), "r", null, null, 0, 1, null, null));
        }
        assertEquals(2, S2SIndexer.sliceEnd(large, 0), "stops once the slice reaches SLICE_BYTES");
        assertEquals(4, S2SIndexer.sliceEnd(large, 3), "at least one doc");
    }
}
