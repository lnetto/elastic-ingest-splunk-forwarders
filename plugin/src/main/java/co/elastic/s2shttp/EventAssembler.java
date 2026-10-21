package co.elastic.s2shttp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongPredicate;
import java.util.regex.Pattern;

/**
 * Turns S2S records into events. For unstructured data a Universal Forwarder ships records of one
 * or more whole lines (final newline stripped), not events: lines are split here and continuation
 * lines (stack traces) are glued onto the previous event, which may have arrived in an earlier
 * record of the same request, so the open event is flushed on the stream's done marker or by
 * {@link #flushAll} at the end of the request: one assembler per request, nothing outlives it.
 * Structured records (INDEXED_EXTRACTIONS) are already one event each and pass straight through.
 */
final class EventAssembler {

    /** An event ready to index. */
    record Doc(
        String host,
        String source,
        String sourcetype,
        String index,
        String channel,
        long timeMillis,
        // Splunk's _time as sent by the forwarder, or null when it sent none (then timeMillis is "now")
        Long splunkTimeMillis,
        String message,
        Map<String, Object> fields,
        String remote,
        // --- provenance, kept so nothing is lost ---
        S2SDecoder.Event record, // the S2S record the (first line of the) event came from
        RequestInfo request, // the HTTP request that carried it
        int recordLine, // line index within that record (0 for structured)
        int recordLines, // lines in that record
        String error, // set on error documents (undecodable body)
        String bodyBase64 // the undecodable body itself
    ) {}

    private record StreamKey(String remote, String host, String source) {}

    private static final class Pending {
        S2SDecoder.Event last;
        RequestInfo request;
        // where the event being built started
        S2SDecoder.Event eventRecord;
        RequestInfo eventRequest;
        int eventLine;
        int eventRecordLines;
        final List<byte[]> event = new ArrayList<>();
        int eventBytes;
    }

    private final Pattern continuation;
    private final int maxEventBytes;
    private final LongPredicate room;
    private final Map<StreamKey, Pending> streams = new HashMap<>();
    private int emitted;

    /**
     * Heap an event takes until it is indexed beyond its text: the document (about 140 bytes measured on
     * Java 21) and its id (about 95). A record of many short lines makes many of them.
     */
    static final int PER_EVENT = 250;

    EventAssembler(String continuationPattern, int maxEventBytes) {
        this(continuationPattern, maxEventBytes, bytes -> true);
    }

    /** {@code room} is asked for {@link #PER_EVENT} per event made; when it says no, {@link S2SDecoder.NoRoom} is thrown. */
    EventAssembler(String continuationPattern, int maxEventBytes, LongPredicate room) {
        this.continuation = continuationPattern == null || continuationPattern.isEmpty() ? null : Pattern.compile(continuationPattern);
        this.maxEventBytes = maxEventBytes;
        this.room = room;
    }

    private void add(List<Doc> out, Doc doc) {
        out.add(doc);
        if (++emitted % 256 == 0 && room.test(256L * PER_EVENT) == false) {
            throw new S2SDecoder.NoRoom();
        }
    }

    List<Doc> accept(String remote, List<S2SDecoder.Event> records, long now) {
        return accept(remote, records, now, null);
    }

    List<Doc> accept(
        String remote,
        List<S2SDecoder.Event> records,
        long now,
        RequestInfo request
    ) {
        List<Doc> out = new ArrayList<>();
        for (S2SDecoder.Event rec : records) {
            if (rec.structured()) {
                if (rec.raw().length > 0) {
                    add(out, doc(rec, remote, new String(rec.raw(), StandardCharsets.UTF_8), now, request, 0, 1));
                }
                continue;
            }
            StreamKey key = new StreamKey(remote, rec.host(), rec.source());
            Pending p = streams.get(key);
            if (rec.done()) {
                if (p != null) {
                    emit(p, remote, out, now);
                    streams.remove(key);
                }
                continue;
            }
            if (p == null) {
                p = new Pending();
                streams.put(key, p);
            }
            p.last = rec;
            p.request = request;
            split(p, rec.raw(), remote, out, now);
        }
        return out;
    }

    /** The events still open at the end of the request. */
    List<Doc> flushAll(long now) {
        List<Doc> out = new ArrayList<>();
        streams.forEach((key, p) -> emit(p, key.remote(), out, now));
        streams.clear();
        return out;
    }

    /** The UF cuts records at line boundaries and strips the final newline: every record ends a line. */
    private void split(Pending p, byte[] raw, String remote, List<Doc> out, long now) {
        int lines = 1;
        for (byte b : raw) {
            if (b == '\n') {
                lines++;
            }
        }
        int start = 0;
        int lineNo = 0;
        for (int i = 0; i <= raw.length; i++) {
            if (i == raw.length || raw[i] == '\n') {
                int end = i > start && raw[i - 1] == '\r' ? i - 1 : i;
                // lines longer than the cap become several events, cut between UTF-8 characters
                for (int from = start; from < end;) {
                    int to = Math.min(end, from + maxEventBytes);
                    while (to < end && to > from + 1 && (raw[to] & 0xC0) == 0x80) {
                        to--;
                    }
                    line(p, Arrays.copyOfRange(raw, from, to), lineNo, lines, remote, out, now);
                    from = to;
                }
                start = i + 1;
                lineNo++;
            }
        }
    }

    private void line(Pending p, byte[] line, int lineNo, int recordLines, String remote, List<Doc> out, long now) {
        if (isBlank(line)) {
            return;
        }
        if (p.event.isEmpty() == false
            && continuation != null
            && p.eventBytes + line.length < maxEventBytes
            && continuation.matcher(new String(line, 0, Math.min(line.length, 64), StandardCharsets.UTF_8)).find()) {
            p.event.add(line);
            p.eventBytes += line.length + 1;
            return;
        }
        emit(p, remote, out, now);
        p.event.add(line);
        p.eventBytes = line.length;
        p.eventRecord = p.last;
        p.eventRequest = p.request;
        p.eventLine = lineNo;
        p.eventRecordLines = recordLines;
    }

    private void emit(Pending p, String remote, List<Doc> out, long now) {
        if (p.event.isEmpty()) {
            return;
        }
        ByteArrayOutputStream b = new ByteArrayOutputStream(p.eventBytes);
        for (int i = 0; i < p.event.size(); i++) {
            if (i > 0) {
                b.write('\n');
            }
            b.writeBytes(p.event.get(i));
        }
        add(
            out,
            doc(
                p.eventRecord,
                remote,
                b.toString(StandardCharsets.UTF_8),
                now,
                p.eventRequest,
                p.eventLine,
                p.eventRecordLines
            )
        );
        p.event.clear();
        p.eventBytes = 0;
    }

    private static boolean isBlank(byte[] line) {
        for (byte c : line) {
            if (c != ' ' && c != '\t' && c != '\r') {
                return false;
            }
        }
        return true;
    }

    private static Doc doc(
        S2SDecoder.Event rec,
        String remote,
        String message,
        long now,
        RequestInfo request,
        int recordLine,
        int recordLines
    ) {
        return new Doc(
            rec.host(),
            rec.source(),
            rec.sourcetype(),
            rec.index(),
            rec.channel(),
            rec.hasTime() ? rec.timeMillis() : now,
            // Splunk's _time only when the forwarder parsed the event (INDEXED_EXTRACTIONS); for raw
            // text the S2S time is the UF's read time, and Splunk's _time comes from the indexer.
            rec.structured() && rec.hasTime() ? rec.timeMillis() : null,
            message,
            rec.fields(),
            Objects.requireNonNullElse(remote, ""),
            rec,
            request,
            recordLine,
            recordLines,
            null,
            null
        );
    }
}
