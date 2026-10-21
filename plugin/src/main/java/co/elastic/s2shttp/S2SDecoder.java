package co.elastic.s2shttp;

import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.BytesRefIterator;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongPredicate;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Decoder for the S2S payload a Universal Forwarder POSTs to {@code /services/collector/s2s}.
 * The wire format of forwarders 8.1 - 10.4, summarised:
 *
 * <pre>
 * body   = 0xf9 zlib(records)            zlib stream is sync-flushed, never finished
 * 0xff   timezone   str
 * 0xfe   meta       id nstr(source::) nstr(host::) nstr(sourcetype::) nstr(channel) n str*n
 * 0xf8   meta       1 id ... as 0xfe; heavy forwarders, for data cloned to more than one output (their events carry a CLONE_CHANNEL field)
 * 0xfc   event      metaId flags [streamId offset seq time]  nfields field* str(raw)
 *                   flags 0 with no fields: a heavy forwarder's marker record, with no raw at all
 * field  tag is a varint; kind 4 ((tag >> 2) & 7) is a metric measurement: str(metric_name:NAME)
 *        offset [digits decimals]
 * flags 0x10000: a metric event (heavy forwarders' log-to-metrics, e.g. their introspection logs into
 *        _metrics): str(values) str(raw), each kind-4 value a little-endian double at values[offset],
 *        and raw the original log line, which the other fields point into as usual
 * </pre>
 */
public final class S2SDecoder {

    static final int BODY_MAGIC = 0xf9;
    static final int OP_TZ = 0xff;
    static final int OP_META = 0xfe;
    static final int OP_EVENT = 0xfc;
    static final int OP_META_CLONE = 0xf8;

    static final int F_TIME_OR_STREAM = 0x0a;
    static final int F_STRUCTURED = 0x40;
    static final int F_METRIC = 0x10000;

    /**
     * Upper bound for one inflated request, protects against zip bombs. A forwarder's batch is
     * batchSize (default 64 KB) plus one event: about 1.5 MB inflated with batchSize = 1 MB.
     */
    static final int MAX_INFLATED = 64 * 1024 * 1024;

    /**
     * Heap a decoded record takes beyond its bytes (the record, its maps, the raw copy's header):
     * about 414 bytes measured on Java 21. A body of tiny records costs far more heap than its size.
     */
    static final int PER_RECORD = 450;

    /** Thrown when the request's memory reservation can't grow for more records or events: answer busy. */
    static final class NoRoom extends RuntimeException {
        NoRoom() {
            super("no memory for this request", null, false, false);
        }
    }

    private S2SDecoder() {}

    public static final class S2SFormatException extends Exception {
        private Batch partialBatch = new Batch(List.of(), 0);

        S2SFormatException(String msg) {
            super(msg);
        }

        /** What was decoded before the failure; the payload is sequential, so its events are complete. */
        public Batch partialBatch() {
            return partialBatch;
        }
    }

    /** One S2S event record: a raw chunk of a file (unstructured) or one parsed event (structured). */
    public record Event(
        String host,
        String source,
        String sourcetype,
        String channel,
        String index,
        int flags,
        long streamId,
        long offset,
        long seq,
        long timeMillis,
        Map<String, Object> fields,
        Map<String, String> meta,
        byte[] raw,
        // --- kept verbatim so nothing the forwarder sent is lost ---
        long timeSec, // S2S time varint (whole seconds), -1 when absent
        List<DatePart> dateParts, // parsed timestamp components (structured only)
        String timezone, // the body's serialized timezone record (0xff)
        List<String> csvHeader // meta tuple CSV header (INDEXED_EXTRACTIONS=csv)
    ) {
        /** Already one event per record (INDEXED_EXTRACTIONS on the forwarder). */
        public boolean structured() {
            return (flags & F_STRUCTURED) != 0;
        }

        /** End-of-data marker for a stream: no stream/time block and an empty raw. */
        public boolean done() {
            return (flags & F_TIME_OR_STREAM) == 0 && raw.length == 0;
        }

        public boolean hasTime() {
            return timeMillis >= 0;
        }
    }

    private record Meta(String source, String host, String sourcetype, String channel, List<String> header) {}

    /** One timestamp component: part id (1 second … 8 zone, 0 subsecond), raw tag, signed value. */
    public record DatePart(int part, int tag, long value) {
        static final String[] NAMES = { "subsecond", "second", "minute", "hour", "year", "month", "mday", "wday", "zone" };

        public String name() {
            return part >= 0 && part < NAMES.length ? NAMES[part] : "part" + part;
        }
    }

    /** Everything decoded from one request body. */
    public record Batch(List<Event> events, int inflatedBytes) {
        public int doneMarkers() {
            return (int) events.stream().filter(Event::done).count();
        }
    }

    public static List<Event> decode(byte[] body) throws S2SFormatException {
        return decodeBatch(body).events();
    }

    /** Decode one request body, keeping its inflated size. */
    public static Batch decodeBatch(byte[] body) throws S2SFormatException {
        return decodeInflated(inflate(new BytesArray(body)), bytes -> true);
    }

    /**
     * The records of an inflated body (see {@link #inflate}). {@code room} is asked for {@link #PER_RECORD}
     * per record as they are decoded; when it says no, {@link NoRoom} is thrown.
     */
    static Batch decodeInflated(byte[] inflated, LongPredicate room) throws S2SFormatException {
        Reader r = new Reader(inflated);
        Map<Long, Meta> metas = new HashMap<>();
        List<Event> events = new ArrayList<>();
        String[] tz = new String[1];
        try {
            decodeRecords(r, metas, events, tz, room);
        } catch (NoRoom e) {
            throw e;
        } catch (S2SFormatException | RuntimeException e) {
            // anything unexpected is a bad body too: answered 200 with an error document, not resent forever
            S2SFormatException f = e instanceof S2SFormatException sfe ? sfe : new S2SFormatException(e + " at " + r.pos);
            f.partialBatch = new Batch(events, inflated.length);
            throw f;
        }
        return new Batch(events, inflated.length);
    }

    private static void decodeRecords(Reader r, Map<Long, Meta> metas, List<Event> events, String[] tz, LongPredicate room)
        throws S2SFormatException {
        while (r.eof() == false) {
            int op = r.u8();
            switch (op) {
                case OP_TZ -> tz[0] = r.str();
                case OP_META, OP_META_CLONE -> {
                    if (op == OP_META_CLONE) {
                        r.uvarint(); // always 1 so far
                    }
                    long id = r.uvarint();
                    String source = strip(r.nstr(), "source::");
                    String host = strip(r.nstr(), "host::");
                    String sourcetype = strip(r.nstr(), "sourcetype::");
                    String channel = r.nstr();
                    int n = r.count();
                    List<String> header = new ArrayList<>(n);
                    for (int i = 0; i < n; i++) {
                        header.add(r.str());
                    }
                    metas.put(id, new Meta(source, host, sourcetype, channel, header));
                }
                case OP_EVENT -> {
                    Event e = event(r, metas, tz[0]);
                    if (e.flags() != 0 || e.raw().length > 0 || e.fields().isEmpty() == false) { // skip heavy-forwarder markers
                        events.add(e);
                        if (events.size() % 256 == 0 && room.test(256L * PER_RECORD) == false) {
                            throw new NoRoom();
                        }
                    }
                }
                default -> throw new S2SFormatException(String.format(java.util.Locale.ROOT, "unknown opcode 0x%02x at %d", op, r.pos - 1));
            }
        }
    }

    private static Event event(Reader r, Map<Long, Meta> metas, String timezone) throws S2SFormatException {
        long metaId = r.uvarint();
        Meta m = metas.get(metaId);
        if (m == null) {
            throw new S2SFormatException("event references unknown meta id " + metaId);
        }
        int flags = (int) r.uvarint();
        long streamId = 0, offset = -1, seq = -1, timeSec = -1;
        if ((flags & F_TIME_OR_STREAM) != 0) {
            streamId = r.uvarint();
            offset = r.uvarint();
            seq = r.uvarint();
            timeSec = r.uvarint();
        }
        int nfields = r.len();
        Map<String, Object> fields = new LinkedHashMap<>();
        Map<String, String> meta = new HashMap<>(4);
        List<Object[]> refs = null; // key, offset, len, escaped
        List<Object[]> metrics = null; // name, offset into raw
        long subsecond = -1;
        List<DatePart> dateParts = List.of();
        for (int i = 0; i < nfields; i++) {
            int tag = r.u8();
            if ((tag & 0x80) != 0) { // varint tag (kind 4 with digits/decimals: 0xb3 0x03)
                tag = (tag & 0x7f) | (r.len() << 7);
            }
            if (tag == 0x04) {
                String k = r.str();
                meta.put(k, r.str());
            } else if ((tag & 0xc0) == 0x40) { // date part; 0x20 marks a negative value (UTC-4 zone)
                long part = r.uvarint();
                long value = r.uvarint();
                if (part == 0) {
                    subsecond = value;
                }
                if (dateParts.isEmpty()) {
                    dateParts = new ArrayList<>(9);
                }
                dateParts.add(new DatePart((int) part, tag, (tag & 0x20) != 0 ? -value : value));
            } else if ((tag & 0x01) != 0) {
                String key = (tag & 0x02) != 0 ? r.str() : header(m, r.len());
                int kind = (tag >> 2) & 0x07;
                switch (kind) {
                    case 0 -> add(fields, key, r.uvarint());
                    case 1 -> add(fields, key, r.str());
                    case 2 -> add(fields, key, constant(r.uvarint()));
                    case 3, 6 -> {
                        if (refs == null) {
                            refs = new ArrayList<>();
                        }
                        // placeholder keeps multi-value order; resolved once raw is read
                        Object[] ref = new Object[] { key, r.len(), r.len(), kind == 6 };
                        refs.add(ref);
                        add(fields, key, ref);
                    }
                    case 4 -> {
                        int at = r.len();
                        if ((tag & 0x180) != 0) { // display digits and decimals
                            r.uvarint();
                            r.uvarint();
                        }
                        if (metrics == null) {
                            metrics = new ArrayList<>();
                        }
                        metrics.add(new Object[] { key.startsWith("metric_name:") ? key.substring("metric_name:".length()) : key, at });
                    }
                    default -> throw new S2SFormatException(String.format(java.util.Locale.ROOT, "unsupported field tag 0x%02x", tag));
                }
            } else {
                throw new S2SFormatException(String.format(java.util.Locale.ROOT, "unknown field tag 0x%02x at %d", tag, r.pos - 1));
            }
        }
        byte[] raw = flags == 0 && nfields == 0 ? new byte[0] : r.bytes(r.len());
        if ((flags & F_METRIC) != 0) {
            byte[] values = raw;
            raw = r.bytes(r.len());
            resolveMetrics(fields, metrics == null ? List.of() : metrics, values);
        }
        if (refs != null) {
            resolveRefs(fields, raw);
        }
        long timeMillis = -1;
        if (timeSec >= 0) {
            timeMillis = timeSec * 1000 + (subsecond > 0 ? subsecondMicros(subsecond) / 1000 : 0);
        }
        return new Event(
            m.host(),
            m.source(),
            m.sourcetype(),
            m.channel(),
            meta.get("_MetaData:Index"),
            flags,
            streamId,
            offset,
            seq,
            timeMillis,
            fields,
            meta,
            raw,
            timeSec,
            dateParts,
            timezone,
            m.header()
        );
    }

    /**
     * Subsecond date part: the fraction's decimal digits with its z leading zeros encoded as z
     * trailing zero bits above a marker bit, {@code v = digits << (z+1) | 1 << z}.
     * .407 -> 815, .015838 -> 63354, .007919 -> 63356. Returns microseconds.
     */
    static long subsecondMicros(long v) {
        if (v <= 0) {
            return 0;
        }
        int z = Long.numberOfTrailingZeros(v);
        String frac = "0".repeat(z) + Long.toString(v >>> (z + 1));
        frac = frac.length() >= 6 ? frac.substring(0, 6) : frac + "0".repeat(6 - frac.length());
        return Long.parseLong(frac);
    }

    /** Kind-2 constants, from INDEXED_EXTRACTIONS=json. */
    static Object constant(long v) {
        return switch ((int) v) {
            case 62 -> Boolean.TRUE;
            case 61 -> Boolean.FALSE;
            case 60 -> "null"; // Splunk indexes JSON null as the literal string "null"
            default -> v;
        };
    }

    @SuppressWarnings("unchecked")
    private static void add(Map<String, Object> fields, String key, Object value) {
        if (fields.containsKey(key) == false) {
            fields.put(key, value);
            return;
        }
        Object cur = fields.get(key);
        List<Object> list;
        if (cur instanceof List<?> l) {
            list = (List<Object>) l;
        } else {
            list = new ArrayList<>(2);
            list.add(cur);
            fields.put(key, list);
        }
        list.add(value);
    }

    /** A metric event's values: little-endian doubles, each a numeric field named after its metric. */
    private static void resolveMetrics(Map<String, Object> fields, List<Object[]> metrics, byte[] values) throws S2SFormatException {
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(values).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        for (Object[] m : metrics) {
            String name = (String) m[0];
            int offset = (Integer) m[1];
            if (offset < 0 || offset > values.length - 8) {
                throw new S2SFormatException("metric " + name + " offset " + offset + " past values of " + values.length);
            }
            add(fields, name, buf.getDouble(offset));
        }
    }

    @SuppressWarnings("unchecked")
    private static void resolveRefs(Map<String, Object> fields, byte[] raw) throws S2SFormatException {
        for (Map.Entry<String, Object> e : fields.entrySet()) {
            Object v = e.getValue();
            if (v instanceof Object[] ref) {
                e.setValue(slice(raw, ref));
            } else if (v instanceof List<?> l) {
                List<Object> list = (List<Object>) l;
                for (int i = 0; i < list.size(); i++) {
                    if (list.get(i) instanceof Object[] ref) {
                        list.set(i, slice(raw, ref));
                    }
                }
            }
        }
    }

    private static String slice(byte[] raw, Object[] ref) throws S2SFormatException {
        int off = (Integer) ref[1], len = (Integer) ref[2];
        if (off < 0 || len < 0 || off + len > raw.length) {
            throw new S2SFormatException("field reference [" + off + "+" + len + "] outside raw of " + raw.length);
        }
        String s = new String(raw, off, len, StandardCharsets.UTF_8);
        return (Boolean) ref[3] ? jsonUnescape(s) : s;
    }

    static String jsonUnescape(String s) {
        if (s.indexOf('\\') < 0) {
            return s;
        }
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                b.append(c);
                continue;
            }
            char n = s.charAt(++i);
            switch (n) {
                case 'n' -> b.append('\n');
                case 't' -> b.append('\t');
                case 'r' -> b.append('\r');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'u' -> {
                    if (i + 4 < s.length() && s.substring(i + 1, i + 5).chars().allMatch(h -> Character.digit(h, 16) >= 0)) {
                        b.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                        i += 4;
                    } else {
                        b.append("\\u");
                    }
                }
                default -> b.append(n); // \" \\ \/
            }
        }
        return b.toString();
    }

    private static String header(Meta m, int i) {
        return i < m.header().size() ? m.header().get(i) : "field" + i;
    }

    private static String strip(String v, String prefix) {
        return v != null && v.startsWith(prefix) ? v.substring(prefix.length()) : v;
    }

    /**
     * Inflate a body in place (no copy of it): the 0xf9 header byte, then a sync-flushed zlib stream.
     * An empty body inflates to nothing.
     */
    static byte[] inflate(BytesReference body) throws S2SFormatException {
        if (body.length() == 0) {
            return new byte[0];
        }
        if ((body.get(0) & 0xff) != BODY_MAGIC) {
            throw new S2SFormatException(String.format(java.util.Locale.ROOT, "unexpected body header byte 0x%02x", body.get(0) & 0xff));
        }
        Inflater inf = new Inflater();
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(MAX_INFLATED, Math.max(64L, body.length() * 6L)));
            byte[] buf = new byte[64 * 1024];
            BytesRefIterator chunks = body.slice(1, body.length() - 1).iterator();
            for (BytesRef chunk = chunks.next(); chunk != null && inf.finished() == false; chunk = chunks.next()) {
                inf.setInput(chunk.bytes, chunk.offset, chunk.length);
                while (inf.finished() == false) {
                    int n = inf.inflate(buf);
                    if (n == 0) {
                        break; // this chunk is used up (or, at the end, the sync-flushed stream is)
                    }
                    out.write(buf, 0, n);
                    if (out.size() > MAX_INFLATED) {
                        throw new S2SFormatException("inflated payload exceeds " + MAX_INFLATED + " bytes");
                    }
                }
            }
            return out.toByteArray();
        } catch (java.io.IOException e) {
            throw new S2SFormatException("body: " + e.getMessage());
        } catch (DataFormatException e) {
            throw new S2SFormatException("zlib: " + e.getMessage());
        } finally {
            inf.end();
        }
    }

    static final class Reader {
        final byte[] b;
        int pos;

        Reader(byte[] b) {
            this.b = b;
        }

        boolean eof() {
            return pos >= b.length;
        }

        int u8() throws S2SFormatException {
            if (pos >= b.length) {
                throw new S2SFormatException("truncated at " + pos);
            }
            return b[pos++] & 0xff;
        }

        long uvarint() throws S2SFormatException {
            long r = 0;
            for (int shift = 0; shift < 70; shift += 7) {
                int x = u8();
                r |= (long) (x & 0x7f) << shift;
                if ((x & 0x80) == 0) {
                    return r;
                }
            }
            throw new S2SFormatException("varint too long at " + pos);
        }

        /** A varint used as a length/count/index: must fit the remaining buffer sensibly. */
        int len() throws S2SFormatException {
            long v = uvarint();
            if (v < 0 || v > Integer.MAX_VALUE) {
                throw new S2SFormatException("length " + v + " out of range at " + pos);
            }
            return (int) v;
        }

        /** A count of items that each take at least a byte: no more than the bytes left. */
        int count() throws S2SFormatException {
            int n = len();
            if (n > b.length - pos) {
                throw new S2SFormatException("count " + n + " past end at " + pos);
            }
            return n;
        }

        byte[] bytes(int n) throws S2SFormatException {
            if (n > b.length - pos) {
                throw new S2SFormatException("length " + n + " past end at " + pos);
            }
            byte[] out = new byte[n];
            System.arraycopy(b, pos, out, 0, n);
            pos += n;
            return out;
        }

        String str() throws S2SFormatException {
            int n = len();
            if (n > b.length - pos) {
                throw new S2SFormatException("string length " + n + " past end at " + pos);
            }
            String s = new String(b, pos, n, StandardCharsets.UTF_8);
            pos += n;
            return s;
        }

        /** Length+1 encoded string; 0 = null. */
        String nstr() throws S2SFormatException {
            int n = len();
            if (n == 0) {
                return null;
            }
            if (n - 1 > b.length - pos) {
                throw new S2SFormatException("string length " + (n - 1) + " past end at " + pos);
            }
            String s = new String(b, pos, n - 1, StandardCharsets.UTF_8);
            pos += n - 1;
            return s;
        }
    }
}
