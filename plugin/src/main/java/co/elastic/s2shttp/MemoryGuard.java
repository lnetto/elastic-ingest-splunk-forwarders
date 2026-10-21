package co.elastic.s2shttp;

import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.breaker.CircuitBreakingException;
import org.elasticsearch.core.Releasable;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Heap a request may use while it is decoded and indexed, so that large batches arriving together get
 * 503 (the forwarder keeps them and resends) instead of running the node out of memory. Each request
 * reserves an estimate on the REQUEST circuit breaker and against a node-wide budget: the breaker
 * alone isn't enough, since the parent breaker only sees memory once it is allocated. A request that
 * is the only one in flight always gets in, however large, so no batch is refused forever.
 */
final class MemoryGuard {

    /** Bytes of heap per inflated byte: the inflated buffer, the events' text and their documents' (fixed costs per event are added as they are made). */
    static final int PER_INFLATED_BYTE = 4;

    private final CircuitBreaker breaker;
    private final long budget;
    private final AtomicLong reserved = new AtomicLong();
    private final AtomicInteger inFlight = new AtomicInteger();

    /** {@code breaker} may be null (tests). */
    MemoryGuard(CircuitBreaker breaker, long budget) {
        this.breaker = breaker;
        this.budget = budget;
    }

    static MemoryGuard forHeap(CircuitBreaker breaker) {
        return new MemoryGuard(breaker, Runtime.getRuntime().maxMemory() / 4);
    }

    Reservation reserve() {
        inFlight.incrementAndGet();
        return new Reservation();
    }

    long reserved() {
        return reserved.get();
    }

    final class Reservation implements Releasable {
        private long bytes;
        private boolean closed;

        /** Grow or shrink this request's reservation to {@code total} bytes; false = no room, nothing changed. */
        synchronized boolean resize(long total) {
            long delta = total - bytes;
            if (delta > 0) {
                if (reserved.addAndGet(delta) > budget && inFlight.get() > 1) {
                    reserved.addAndGet(-delta);
                    return false;
                }
                if (breaker != null) {
                    try {
                        breaker.addEstimateBytesAndMaybeBreak(delta, "splunk_forwarders");
                    } catch (CircuitBreakingException e) {
                        reserved.addAndGet(-delta);
                        return false;
                    }
                }
            } else if (delta < 0) {
                reserved.addAndGet(delta);
                if (breaker != null) {
                    breaker.addWithoutBreaking(delta);
                }
            }
            bytes = total;
            return true;
        }

        /** Add {@code delta} bytes to this request's reservation; false = no room, nothing changed. */
        synchronized boolean grow(long delta) {
            return resize(bytes + delta);
        }

        @Override
        public synchronized void close() {
            if (closed == false) {
                closed = true;
                resize(0);
                inFlight.decrementAndGet();
            }
        }
    }
}
