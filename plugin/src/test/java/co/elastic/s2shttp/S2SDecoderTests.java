package co.elastic.s2shttp;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;

import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.xcontent.json.JsonXContent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class S2SDecoderTests {

    /** Sample forwarder request bodies, kept outside this repo; tests that need them skip when they are absent. */
    static final Path SAMPLES = Path.of(System.getProperty("s2s.samples", "src/test/resources/samples"));

    static List<Path> runs() throws IOException {
        assumeTrue(Files.isDirectory(SAMPLES), "no samples at " + SAMPLES);
        try (Stream<Path> s = Files.list(SAMPLES)) {
            return s.filter(Files::isDirectory).sorted().toList();
        }
    }

    static List<Path> bodies(Path run) throws IOException {
        assumeTrue(Files.isDirectory(run), "no samples at " + run);
        try (Stream<Path> s = Files.list(run)) {
            return s.filter(p -> p.toString().endsWith(".bin")).sorted().toList();
        }
    }

    @Test
    void everySampleBodyDecodes() throws Exception {
        int n = 0;
        for (Path run : runs()) {
            for (Path bin : bodies(run)) {
                List<S2SDecoder.Event> events = S2SDecoder.decode(Files.readAllBytes(bin));
                assertFalse(events.isEmpty(), bin.toString());
                for (S2SDecoder.Event e : events) {
                    assertTrue(e.host() != null && e.host().isEmpty() == false, bin.toString());
                    assertTrue(e.sourcetype() != null && e.source() != null, bin.toString());
                    if (e.done() == false) {
                        assertTrue(e.hasTime(), bin + " " + e.sourcetype());
                        assertTrue(e.index() != null, bin.toString());
                    }
                }
                n++;
            }
        }
        assertTrue(n >= 5, "expected fixtures, found " + n);
    }

    /**
     * Decode + assembly must reproduce the reviewed expected output event for event. After an
     * intended decoder change, refresh it with: ./build-plugin.sh test -Dupdate.golden=true
     */
    @Test
    void matchesGoldenEvents() throws Exception {
        for (Path run : runs()) {
            EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
            List<EventAssembler.Doc> docs = new ArrayList<>();
            for (Path bin : bodies(run)) {
                docs.addAll(asm.accept("file", S2SDecoder.decode(Files.readAllBytes(bin)), 0));
            }
            docs.addAll(asm.flushAll(0));
            if (Boolean.getBoolean("update.golden")) {
                writeGolden(run.resolve("expected-events.ndjson.gz"), docs);
                continue;
            }

            List<Map<String, Object>> expected = readGolden(run.resolve("expected-events.ndjson.gz"));
            assertEquals(expected.size(), docs.size(), run + " event count");
            for (int i = 0; i < docs.size(); i++) {
                EventAssembler.Doc d = docs.get(i);
                Map<String, Object> e = expected.get(i);
                @SuppressWarnings("unchecked")
                Map<String, Object> sp = (Map<String, Object>) e.get("splunk");
                String where = run.getFileName() + "#" + i;
                assertEquals(e.get("message"), d.message(), where);
                assertEquals(sp.get("sourcetype"), d.sourcetype(), where);
                assertEquals(sp.get("source"), d.source(), where);
                assertEquals(sp.get("host"), d.host(), where);
                assertEquals(sp.get("index"), d.index(), where);
                assertEquals(sp.get("channel"), d.channel(), where);
                assertEquals(e.get("@timestamp"), Instant.ofEpochMilli(d.timeMillis()).toString().replaceFirst("(\\.\\d{3})?Z$", "") + ms(d), where);
                Object ef = sp.get("fields");
                assertEquals(normalize(ef == null ? Map.of() : ef), normalize(d.fields()), where);
            }
        }
    }

    private static String ms(EventAssembler.Doc d) {
        return String.format(java.util.Locale.ROOT, ".%03dZ", d.timeMillis() % 1000);
    }

    /** Compare numbers by value regardless of Integer/Long boxing. */
    private static Object normalize(Object o) {
        if (o instanceof Map<?, ?> m) {
            java.util.TreeMap<String, Object> out = new java.util.TreeMap<>();
            m.forEach((k, v) -> out.put(k.toString(), normalize(v)));
            return out;
        }
        if (o instanceof List<?> l) {
            return l.stream().map(S2SDecoderTests::normalize).toList();
        }
        if (o instanceof Number n) {
            return n.longValue();
        }
        return o;
    }

    private static void writeGolden(Path gz, List<EventAssembler.Doc> docs) throws IOException {
        try (var out = new java.io.PrintStream(new java.util.zip.GZIPOutputStream(Files.newOutputStream(gz)), false, StandardCharsets.UTF_8)) {
            for (EventAssembler.Doc d : docs) {
                Map<String, Object> splunk = new java.util.LinkedHashMap<>();
                splunk.put("index", d.index());
                splunk.put("host", d.host());
                splunk.put("source", d.source());
                splunk.put("sourcetype", d.sourcetype());
                splunk.put("channel", d.channel());
                if (d.fields().isEmpty() == false) {
                    splunk.put("fields", d.fields());
                }
                Map<String, Object> doc = new java.util.LinkedHashMap<>();
                doc.put("@timestamp", Instant.ofEpochMilli(d.timeMillis()).toString().replaceFirst("(\\.\\d{3})?Z$", "") + ms(d));
                doc.put("message", d.message());
                doc.put("splunk", splunk);
                try (var b = org.elasticsearch.xcontent.XContentFactory.jsonBuilder()) {
                    out.println(org.elasticsearch.common.Strings.toString(b.map(doc)));
                }
            }
        }
    }

    private static List<Map<String, Object>> readGolden(Path gz) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        try (
            BufferedReader r = new BufferedReader(
                new InputStreamReader(new GZIPInputStream(Files.newInputStream(gz)), StandardCharsets.UTF_8)
            )
        ) {
            String line;
            while ((line = r.readLine()) != null) {
                out.add(XContentHelper.convertToMap(JsonXContent.jsonXContent, line, false));
            }
        }
        return out;
    }

    @Test
    void typedJsonFields() throws Exception {
        S2SDecoder.Event types = null;
        for (Path bin : bodies(SAMPLES.resolve("uf-10.4.3-edt"))) {
            types = S2SDecoder.decode(Files.readAllBytes(bin))
                .stream()
                .filter(e -> "loggen:types".equals(e.sourcetype()) && e.raw().length > 0)
                .findFirst()
                .orElse(null);
            if (types != null) {
                break;
            }
        }
        assertTrue(types != null, "no loggen:types event in the sample");
        Map<String, Object> f = types.fields();
        assertEquals(Boolean.FALSE, f.get("no"));
        assertEquals(Boolean.TRUE, f.get("ok"));
        assertEquals("null", f.get("nil")); // as Splunk indexes it
        assertEquals("-0.5", f.get("nf"));
        assertEquals("1.25", f.get("flt"));
        assertEquals(12345678901234L, f.get("big"));
        assertEquals("", f.get("e"));
        assertEquals("a\"b", f.get("s"));
        assertTrue(types.structured());
    }

    /** A heavy forwarder (Splunk Enterprise with httpout) sends 0xf8 meta, marker records and metric fields. */
    @Test
    void heavyForwarderMetrics() throws Exception {
        assumeTrue(Files.isDirectory(SAMPLES.resolve("hf-10.4.3")), "no samples at " + SAMPLES);
        List<S2SDecoder.Event> events = S2SDecoder.decode(Files.readAllBytes(SAMPLES.resolve("hf-10.4.3/00001.bin")));
        S2SDecoder.Event m = events.stream()
            .filter(e -> e.fields().containsKey("spl.intr.resource_usage.PerProcess.data.t_count"))
            .findFirst()
            .orElseThrow();
        assertEquals(83.0, m.fields().get("spl.intr.resource_usage.PerProcess.data.t_count"));
        assertEquals(2.3, m.fields().get("spl.intr.resource_usage.PerProcess.data.pct_cpu"));
        assertEquals("_metrics", m.index());
        String text = new String(m.raw(), java.nio.charset.StandardCharsets.UTF_8); // the original log line
        assertTrue(text.startsWith("{\"datetime\":"), text);
        assertEquals("INFO", m.fields().get("log_level"));
        assertTrue(events.stream().anyMatch(e -> "cisco:asa".equals(e.sourcetype()) || "splunkd".equals(e.sourcetype())));
    }

    @Test
    void subsecondEncoding() {
        assertEquals(407000, S2SDecoder.subsecondMicros(815));
        assertEquals(210000, S2SDecoder.subsecondMicros(421));
        assertEquals(15838, S2SDecoder.subsecondMicros(63354));
        assertEquals(7919, S2SDecoder.subsecondMicros(63356));
        assertEquals(102947, S2SDecoder.subsecondMicros(205895));
    }

    @Test
    void rejectsGarbage() {
        assertThrows(S2SDecoder.S2SFormatException.class, () -> S2SDecoder.decode(new byte[] { 1, 2, 3 }));
        assertThrows(S2SDecoder.S2SFormatException.class, () -> S2SDecoder.decode(new byte[] { (byte) 0xf9, 1, 2, 3 }));
    }

    @Test
    void corruptBodyIsAnErrorThatKeepsWhatDecoded() throws Exception {
        byte[] body = Files.readAllBytes(bodies(SAMPLES.resolve("uf-10.4.3-edt")).get(0));
        // valid records followed by an unknown record type (a truncated body can end on a record
        // boundary and decode cleanly, so corrupt it deterministically instead)
        byte[] inflated = S2SDecoder.inflate(new org.elasticsearch.common.bytes.BytesArray(body));
        java.io.ByteArrayOutputStream z = new java.io.ByteArrayOutputStream();
        z.write(0xf9);
        try (java.util.zip.DeflaterOutputStream d = new java.util.zip.DeflaterOutputStream(z)) {
            d.write(inflated);
            d.write(new byte[] { (byte) 0x99, 1, 2, 3 });
        }
        S2SDecoder.S2SFormatException e = assertThrows(S2SDecoder.S2SFormatException.class, () -> S2SDecoder.decode(z.toByteArray()));
        assertTrue(e.getMessage().contains("0x99"), e.getMessage());
        assertEquals(S2SDecoder.decode(body).size(), e.partialBatch().events().size(), "every record before the corruption is recovered");
    }

    @Test
    void recordsEndAtLineBoundariesAndContinuationsSpanRecords() {
        EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
        List<EventAssembler.Doc> out = new ArrayList<>();
        // UF strips the final newline of each record: "tail" is a complete line, not a fragment
        out.addAll(asm.accept("r", List.of(chunk("line one\nERROR boom\n\tat a.b(C.java:1)")), 0));
        out.addAll(asm.accept("r", List.of(chunk("\tat c.d(E.java:2)\r\ntail")), 10));
        out.addAll(asm.accept("r", List.of(chunk("next")), 20));
        assertEquals(
            List.of("line one", "ERROR boom\n\tat a.b(C.java:1)\n\tat c.d(E.java:2)", "tail"),
            out.stream().map(EventAssembler.Doc::message).toList()
        );
        out.addAll(asm.flushAll(30)); // the end of the request flushes the event still open
        assertEquals("next", out.get(out.size() - 1).message());
        assertTrue(asm.flushAll(40).isEmpty());
    }

    /** Regression: a record's last line used to be glued onto the next record's first line. */
    @Test
    void sampleLongLinesStayOwnEvents() throws Exception {
        for (Path run : runs().stream().filter(r -> r.getFileName().toString().startsWith("uf-")).toList()) { // loggen:multi is UF-only
            EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
            List<EventAssembler.Doc> docs = new ArrayList<>();
            for (Path bin : bodies(run)) {
                docs.addAll(asm.accept("file", S2SDecoder.decode(Files.readAllBytes(bin)), 0));
            }
            docs.addAll(asm.flushAll(0));
            List<EventAssembler.Doc> multi = docs.stream().filter(d -> "loggen:multi".equals(d.sourcetype())).toList();
            assertFalse(multi.isEmpty(), run.toString());
            for (EventAssembler.Doc d : multi) {
                String m = d.message();
                assertTrue(m.startsWith("2026-"), run + ": " + m.substring(0, Math.min(80, m.length())));
                assertFalse(m.contains("emoji=\uD83D\uDE80" + "2026"), run + " glued lines");
                if (m.contains(" long seq=")) {
                    assertEquals(1, m.split("\n").length, run + " long line merged with others");
                }
            }
        }
    }

    /** Records of two files interleaved in one request: an indented line continues its own file's event, and a done marker closes only its file's. */
    @Test
    void interleavedStreamsStayApart() {
        EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
        List<EventAssembler.Doc> out = new ArrayList<>(asm.accept("r", List.of(
            chunk("/a.log", "a1 ERROR"), chunk("/b.log", "b1"), chunk("/a.log", "\tat a.A(A.java:1)"), done("/b.log"), chunk("/b.log", "\tb2")
        ), 0));
        assertEquals(List.of("b1"), out.stream().map(EventAssembler.Doc::message).toList(), "the done marker flushes /b.log only");
        out.addAll(asm.flushAll(0)); // the rest, in no particular order
        assertEquals(
            java.util.Set.of("/b.log b1", "/a.log a1 ERROR\n\tat a.A(A.java:1)", "/b.log \tb2"),
            out.stream().map(d -> d.source() + " " + d.message()).collect(java.util.stream.Collectors.toSet())
        );
        assertEquals(3, out.size());
    }

    private static S2SDecoder.Event chunk(String source, String s) {
        S2SDecoder.Event e = chunk(s);
        return new S2SDecoder.Event(e.host(), source, e.sourcetype(), e.channel(), e.index(), e.flags(), e.streamId(), e.offset(), e.seq(),
            e.timeMillis(), e.fields(), e.meta(), e.raw(), e.timeSec(), e.dateParts(), e.timezone(), e.csvHeader());
    }

    /** A stream's end-of-data marker, as a universal forwarder sends it (flags 0x231, no position, empty raw). */
    private static S2SDecoder.Event done(String source) {
        return new S2SDecoder.Event("h", source, "st", "1", "main", 0x231, 0, -1, -1, -1, Map.of(), Map.of(), new byte[0], -1, List.of(), null,
            List.of());
    }

    @Test
    void assemblerSplitsOversizedLines() {
        EventAssembler asm = new EventAssembler("", 1024);
        byte[] big = new byte[2500];
        java.util.Arrays.fill(big, (byte) 'A');
        List<EventAssembler.Doc> out = new ArrayList<>(asm.accept("r", List.of(chunk(new String(big, StandardCharsets.US_ASCII))), 0));
        out.addAll(asm.flushAll(0));
        assertEquals(List.of(1024, 1024, 452), out.stream().map(d -> d.message().length()).toList());
    }

    /** A cut never splits a UTF-8 character: each part decodes back to its text. */
    @Test
    void oversizedLinesAreCutBetweenCharacters() {
        EventAssembler asm = new EventAssembler("", 1024);
        String line = "é".repeat(1500); // 2 bytes each: 1024 would end inside one
        List<EventAssembler.Doc> out = new ArrayList<>(asm.accept("r", List.of(chunk(line)), 0));
        out.addAll(asm.flushAll(0));
        assertEquals(line, String.join("", out.stream().map(EventAssembler.Doc::message).toList()));
        assertEquals(List.of(512, 512, 476), out.stream().map(d -> d.message().length()).toList());
    }

    private static S2SDecoder.Event chunk(String s) {
        return new S2SDecoder.Event(
            "h",
            "/var/log/x.log",
            "st",
            "1",
            "main",
            0x23b,
            42,
            0,
            1,
            1_000_000L,
            Map.of(),
            Map.of(),
            s.getBytes(StandardCharsets.UTF_8),
            -1,
            List.of(),
            null,
            List.of()
        );
    }

    @Test
    void jsonUnescape() {
        assertEquals("a\"b\\c\né", S2SDecoder.jsonUnescape("a\\\"b\\\\c\\n\\u00e9"));
    }

    @Test
    void zipBombIsRefused() {
        // 80 MB of zeros deflates to ~80 KB; the decoder must stop at MAX_INFLATED, not allocate it all
        java.util.zip.Deflater def = new java.util.zip.Deflater(9);
        def.setInput(new byte[80 * 1024 * 1024]);
        def.finish();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(S2SDecoder.BODY_MAGIC);
        byte[] buf = new byte[64 * 1024];
        while (def.finished() == false) {
            out.write(buf, 0, def.deflate(buf));
        }
        S2SDecoder.S2SFormatException e = assertThrows(S2SDecoder.S2SFormatException.class, () -> S2SDecoder.decodeBatch(out.toByteArray()));
        assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
    }

    /** A JSON field with a broken \\u escape keeps the text instead of failing the whole body. */
    @Test
    void badUnicodeEscapeInAJsonField() throws Exception {
        assertEquals("a\\uZZ\\u12", S2SDecoder.jsonUnescape("a\\uZZ\\u12"));
        byte[] body = Files.readAllBytes(bodies(SAMPLES.resolve("uf-10.4.3-edt")).get(0));
        byte[] raw = "{\"k\":\"\\uZZZZ\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream rec = new java.io.ByteArrayOutputStream();
        rec.writeBytes(new byte[] { (byte) 0xfe, 0x7f, 2, 's', 2, 'h', 3, 's', 't', 0, 0 }); // meta 127: source s, host h, sourcetype st
        rec.writeBytes(new byte[] { (byte) 0xfc, 0x7f, 0x4a, 1, 1, 0, 1, 1, 0x1b, 1, 'k', 6, 6 }); // structured event, field k = raw[6..12], JSON-escaped
        rec.write(raw.length);
        rec.writeBytes(raw);
        java.io.ByteArrayOutputStream z = new java.io.ByteArrayOutputStream();
        z.write(0xf9);
        try (java.util.zip.DeflaterOutputStream d = new java.util.zip.DeflaterOutputStream(z)) {
            d.write(S2SDecoder.inflate(new org.elasticsearch.common.bytes.BytesArray(body)));
            d.write(rec.toByteArray());
        }
        List<S2SDecoder.Event> events = S2SDecoder.decode(z.toByteArray());
        assertEquals(S2SDecoder.decode(body).size() + 1, events.size());
        assertEquals("\\uZZZZ", events.get(events.size() - 1).fields().get("k"));
    }
}
