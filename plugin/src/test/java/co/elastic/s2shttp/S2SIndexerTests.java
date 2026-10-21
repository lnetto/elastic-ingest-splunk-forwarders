package co.elastic.s2shttp;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class S2SIndexerTests {

    private static EventAssembler.Doc doc(Long splunkTime) {
        long ts = splunkTime != null ? splunkTime : 1_790_000_000_000L;
        return new EventAssembler.Doc("uf01", "/var/log/x.log", "st", "main", "1", ts, splunkTime, "msg", Map.of(), "10.0.0.1",
            null, null, 0, 1, null, null);
    }

    @Test
    void longSourcetypeStillMakesAValidStreamName() {
        assertEquals(S2SIndexer.MAX_NAME_PART, S2SIndexer.sanitize("a".repeat(300)).length());
        assertEquals("cisco_asa", S2SIndexer.sanitize("cisco:asa"));
    }

    /**
     * A placeholder in the namespace stays within the plugin's index template (logs-splunk.s2s-*), as the README
     * advises; one in the dataset makes a stream the template doesn't cover.
     */
    @Test
    void placeholderInTheNamespaceKeepsThePluginTemplate() {
        S2SIndexer ix = new S2SIndexer(null, null, Settings.builder().put("xpack.security.enabled", false)
            .put("splunk_forwarders.target", "logs-splunk.s2s-{sourcetype}").build());
        EventAssembler.Doc d = new EventAssembler.Doc("uf01", "/var/log/x.log", "Cisco:ASA-v2", "_internal", "1", 0, null, "msg", Map.of(),
            "", null, null, 0, 1, null, null);
        assertEquals("logs-splunk.s2s-cisco_asa_v2", ix.resolveTarget(d));
        assertTrue(org.elasticsearch.common.regex.Regex.simpleMatch("logs-splunk.s2s-*", ix.resolveTarget(d)));
        ix.setTarget("logs-splunk.{sourcetype}-{index}");
        assertEquals("logs-splunk.cisco_asa_v2-x_internal", ix.resolveTarget(d));
        assertFalse(org.elasticsearch.common.regex.Regex.simpleMatch("logs-splunk.s2s-*", ix.resolveTarget(d)));
        ix.setTarget("logs-splunk.s2s-{index}");
        assertEquals("logs-splunk.s2s-unknown", ix.resolveTarget(new EventAssembler.Doc(null, null, null, null, null, 0, null, "m", Map.of(),
            "", null, null, 0, 0, null, null)), "an error document has no index");
        S2SHttpSettings.validateTarget("logs-splunk.s2s-{sourcetype}");
    }

    @Test
    void targetNoEventCanBeWrittenToIsRefused() {
        for (String bad : List.of("Bad-Target", "bad target", "", "logs-splunk.{nope}-default", "_x", "a/b")) {
            assertThrows(IllegalArgumentException.class, () -> S2SHttpSettings.validateTarget(bad), bad);
        }
        S2SHttpSettings.validateTarget("logs-splunk.{sourcetype}-default");
        S2SHttpSettings.validateTarget("logs-myapp-default");
        assertEquals("logs-splunk.s2s-default", S2SHttpSettings.TARGET.getDefault(Settings.EMPTY));
    }

    @Test
    @SuppressWarnings("unchecked")
    void splunkTimeOnlyWhenTheForwarderSentOne() {
        Map<String, Object> withTime = S2SIndexer.toSource(doc(1_704_240_001_111L));
        assertEquals("2024-01-03T00:00:01.111Z", ((Map<String, Object>) withTime.get("splunk")).get("time"));
        assertEquals("2024-01-03T00:00:01.111Z", withTime.get("@timestamp"));

        Map<String, Object> readTime = S2SIndexer.toSource(doc(null));
        assertFalse(((Map<String, Object>) readTime.get("splunk")).containsKey("time"));
    }

    /** Nothing the forwarder sent is dropped: request, record and body-level data all land in the doc. */
    @Test
    @SuppressWarnings("unchecked")
    void keepsEverythingButCredentials() throws Exception {
        // first body that carries a loggen:types event
        byte[] body = null;
        for (java.nio.file.Path bin : S2SDecoderTests.bodies(S2SDecoderTests.SAMPLES.resolve("uf-10.4.3-edt"))) {
            byte[] b = java.nio.file.Files.readAllBytes(bin);
            if (S2SDecoder.decode(b).stream().anyMatch(e -> "loggen:types".equals(e.sourcetype()) && e.raw().length > 0)) {
                body = b;
                break;
            }
        }
        assertTrue(body != null);
        S2SDecoder.Batch batch = S2SDecoder.decodeBatch(body);
        Map<String, String> headers = new java.util.HashMap<>();
        headers.put("Authorization", "Splunk a3f5c2e1-7b4d-4e8f-9c6a-1d2e3f4a5b6c");
        headers.put("Cookie", "session=abc");
        headers.put("X-Some-Token", "t");
        headers.put("__splunk_app_version", "splunkforwarder-10.4.3-4174a2deda5d");
        headers.put("__splunk_app_name", "forwarder_s2shttp_out");
        headers.put("X-Forwarded-For", "203.0.113.10, 10.0.0.1");
        RequestInfo req = RequestInfo.of("node-1", "10.0.0.1", headers, body.length, batch, 1_790_000_000_000L, sha -> null);
        EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
        java.util.List<EventAssembler.Doc> docs = new java.util.ArrayList<>(asm.accept("203.0.113.10", batch.events(), 0, req));
        docs.addAll(asm.flushAll(0));

        EventAssembler.Doc json = docs.stream().filter(d -> "loggen:types".equals(d.sourcetype())).findFirst().orElseThrow();
        Map<String, Object> src = S2SIndexer.toSource(json);
        Map<String, Object> splunk = (Map<String, Object>) src.get("splunk");
        Map<String, Object> r = (Map<String, Object>) splunk.get("request");
        Map<String, String> h = (Map<String, String>) r.get("headers");
        assertFalse(h.containsKey("authorization"));
        assertFalse(h.containsKey("cookie"));
        assertFalse(h.containsKey("x-some-token"));
        assertFalse(src.toString().contains("a3f5c2e1-7b4d-4e8f-9c6a-1d2e3f4a5b6c"), "token must never be stored");
        assertEquals(RequestInfo.sha256("a3f5c2e1-7b4d-4e8f-9c6a-1d2e3f4a5b6c"), splunk.get("token_sha256"));
        assertFalse(r.containsKey("token_sha256"));
        assertEquals("203.0.113.10, 10.0.0.1", r.get("x_forwarded_for"));
        assertEquals(body.length, r.get("bytes"));
        assertEquals(batch.events().size(), r.get("records"));
        Map<String, Object> agent = (Map<String, Object>) src.get("agent");
        assertEquals("10.4.3", agent.get("version"));
        assertEquals("splunkforwarder-10.4.3-4174a2deda5d", ((Map<String, Object>) agent.get("build")).get("original"));
        Map<String, Object> s2s = (Map<String, Object>) splunk.get("s2s");
        assertTrue(((String) s2s.get("timezone")).startsWith("### SERIALIZED TIMEZONE FORMAT"));
        assertFalse(((java.util.List<?>) s2s.get("date_parts")).isEmpty());
        assertTrue(((Map<String, Object>) splunk.get("meta")).containsKey("_path"));
        Map<String, Object> fields = (Map<String, Object>) splunk.get("fields");
        assertTrue(fields.containsKey("date_second") && fields.containsKey("date_year"));
        assertEquals("2026", fields.get("date_year"));
        assertEquals("october", fields.get("date_month"));   // the sample is from 2026-10-01
        assertEquals("thursday", fields.get("date_wday"));
        assertEquals("0", fields.get("date_zone"));           // "...Z" parsed with %z
        assertTrue(src.containsKey("event"));

        // the rest of the request's events: no copy of its headers or timezone record, the same request id
        Map<String, Object> later = (Map<String, Object>) S2SIndexer.toSource(json, false).get("splunk");
        Map<String, Object> laterReq = (Map<String, Object>) later.get("request");
        assertFalse(laterReq.containsKey("headers"));
        assertFalse(((Map<String, Object>) later.get("s2s")).containsKey("timezone"));
        assertEquals(r.get("id"), laterReq.get("id"));
        assertEquals("splunkforwarder-10.4.3-4174a2deda5d",
            ((Map<String, Object>) ((Map<String, Object>) S2SIndexer.toSource(json, false).get("agent")).get("build")).get("original"));

        EventAssembler.Doc line = docs.stream().filter(d -> "loggen:app".equals(d.sourcetype())).findFirst().orElseThrow();
        Map<String, Object> ls2s = (Map<String, Object>) ((Map<String, Object>) S2SIndexer.toSource(line).get("splunk")).get("s2s");
        assertEquals(0, ls2s.get("record_line"));
        assertTrue((Integer) ls2s.get("record_lines") >= 1);
        assertTrue(ls2s.containsKey("stream_id") && ls2s.containsKey("offset"));
    }

    /**
     * agent.type is the build up to its first "-", in both metadata modes; agent.build.original, the build
     * as sent, only with full. The values are what a 10.4.3 universal forwarder and a 10.6.0.5 Splunk Enterprise
     * heavy forwarder send over [httpout].
     */
    @Test
    @SuppressWarnings("unchecked")
    void agentTypeIsTheProductInTheBuild() throws Exception {
        assertEquals("splunkforwarder", RequestInfo.agentType("splunkforwarder-10.4.3-4174a2deda5d"));
        assertEquals("splunk", RequestInfo.agentType("splunk-10.6.0.5-86587d4e3b27"));
        assertEquals("splunk", RequestInfo.agentType("splunk"));
        assertEquals("something", RequestInfo.agentType("something-else"));
        assertEquals(null, RequestInfo.agentType("-10.4.3"));
        assertEquals(null, RequestInfo.agentType(""));
        assertEquals(null, RequestInfo.agentType(null));

        org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.isDirectory(S2SDecoderTests.SAMPLES), "no samples");
        byte[] body = java.nio.file.Files.readAllBytes(S2SDecoderTests.SAMPLES.resolve("hf-10.4.3/00001.bin"));
        S2SDecoder.Batch batch = S2SDecoder.decodeBatch(body);
        java.util.Map<String, Map<String, Object>> expected = new java.util.LinkedHashMap<>();
        expected.put("splunk-10.6.0.5-86587d4e3b27",
            Map.of("type", "splunk", "version", "10.6.0.5", "build", Map.of("original", "splunk-10.6.0.5-86587d4e3b27")));
        expected.put("splunkforwarder-10.4.3-4174a2deda5d",
            Map.of("type", "splunkforwarder", "version", "10.4.3", "build", Map.of("original", "splunkforwarder-10.4.3-4174a2deda5d")));
        expected.put("nodash", Map.of("type", "nodash", "version", "nodash", "build", Map.of("original", "nodash")));
        expected.put(null, Map.of());
        for (var c : expected.entrySet()) {
            Map<String, String> headers = new java.util.HashMap<>();
            if (c.getKey() != null) {
                headers.put("__splunk_app_version", c.getKey());
            }
            RequestInfo req = RequestInfo.of("node-1", "10.0.0.1", headers, body.length, batch, 1_790_000_000_000L, sha -> null);
            EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
            List<EventAssembler.Doc> docs = new java.util.ArrayList<>(asm.accept("10.0.0.1", batch.events(), 0, req));
            docs.addAll(asm.flushAll(0));
            assertEquals(c.getValue(), S2SIndexer.toSource(docs.get(0), true, true).get("agent"), c.getKey() + " full");
            Map<String, Object> minimal = new java.util.HashMap<>(c.getValue());
            minimal.remove("build");
            assertEquals(minimal, S2SIndexer.toSource(docs.get(0), true, false).get("agent"), c.getKey() + " minimal");
        }
    }

    /** Metric events are marked event.kind: metric, so a pipeline can route them to a metrics stream. */
    @Test
    @SuppressWarnings("unchecked")
    void metricEventsAreMarked() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.isDirectory(S2SDecoderTests.SAMPLES.resolve("hf-10.4.3")), "no samples");
        byte[] body = java.nio.file.Files.readAllBytes(S2SDecoderTests.SAMPLES.resolve("hf-10.4.3/00001.bin"));
        S2SDecoder.Batch batch = S2SDecoder.decodeBatch(body);
        RequestInfo req = RequestInfo.of("node-1", "10.0.0.1", Map.of(), body.length, batch, 1_790_000_000_000L, sha -> null);
        EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
        List<EventAssembler.Doc> docs = new java.util.ArrayList<>(asm.accept("10.0.0.1", batch.events(), 0, req));
        docs.addAll(asm.flushAll(0));
        int metrics = 0;
        int others = 0;
        for (EventAssembler.Doc d : docs) {
            Map<String, Object> event = (Map<String, Object>) S2SIndexer.toSource(d, true, false).get("event");
            if (d.record() != null && (d.record().flags() & S2SDecoder.F_METRIC) != 0) {
                assertEquals("metric", event.get("kind"));
                assertTrue(d.fields().values().stream().anyMatch(v -> v instanceof Double), "a metric event has a numeric value");
                metrics++;
            } else {
                assertFalse(event.containsKey("kind"), event::toString);
                others++;
            }
        }
        assertTrue(metrics > 0 && others > 0, metrics + " metric and " + others + " other events");
    }

    /**
     * splunk_forwarders.metadata: minimal (the default) keeps the event and the token's name, not the record
     * or the request; the ids are the same as with full, so switching doesn't index a resent batch twice.
     */
    @Test
    @SuppressWarnings("unchecked")
    void minimalMetadataKeepsTheEventOnly() throws Exception {
        assertEquals("minimal", S2SHttpSettings.METADATA.get(Settings.EMPTY));
        assertThrows(IllegalArgumentException.class,
            () -> S2SHttpSettings.METADATA.get(Settings.builder().put("splunk_forwarders.metadata", "none").build()));
        byte[] body = java.nio.file.Files.readAllBytes(S2SDecoderTests.bodies(S2SDecoderTests.SAMPLES.resolve("uf-10.4.3-edt")).get(0));
        S2SDecoder.Batch batch = S2SDecoder.decodeBatch(body);
        Map<String, String> headers = Map.of("Authorization", "Splunk t", "__splunk_app_version", "splunkforwarder-10.4.3-4174a2deda5d",
            "X-Forwarded-For", "203.0.113.10");
        RequestInfo req = RequestInfo.of("node-1", "10.0.0.1", headers, body.length, batch, 1_790_000_000_000L, sha -> "dc1");
        EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
        List<EventAssembler.Doc> docs = new java.util.ArrayList<>(asm.accept("203.0.113.10", batch.events(), 0, req));
        docs.addAll(asm.flushAll(0));
        assertFalse(docs.isEmpty());

        Settings.Builder base = Settings.builder().put("xpack.security.enabled", false);
        S2SIndexer minimal = new S2SIndexer(null, null, base.build());
        S2SIndexer full = new S2SIndexer(null, null, base.put("splunk_forwarders.metadata", "full").build());
        var minimalBulk = minimal.toBulk(docs, S2SIndexer.docIds(docs), 0);
        var fullBulk = full.toBulk(docs, S2SIndexer.docIds(docs), 0);
        for (int i = 0; i < docs.size(); i++) {
            assertEquals(fullBulk.requests().get(i).id(), minimalBulk.requests().get(i).id());
            Map<String, Object> src = ((org.elasticsearch.action.index.IndexRequest) minimalBulk.requests().get(i)).sourceAsMap();
            assertTrue(java.util.Set.of("@timestamp", "message", "host", "log", "splunk", "agent", "event").containsAll(src.keySet()), src.keySet()::toString);
            Map<String, Object> splunk = (Map<String, Object>) src.get("splunk");
            for (String gone : List.of("request", "s2s", "meta", "token_sha256")) {
                assertFalse(splunk.containsKey(gone), gone);
            }
            assertEquals("dc1", splunk.get("token_name"));
            assertEquals(Map.of("type", "splunkforwarder", "version", "10.4.3"), src.get("agent"));
            assertEquals(Map.of("module", "splunk_forwarders"), src.get("event"));
            Map<String, Object> fullSrc = ((org.elasticsearch.action.index.IndexRequest) fullBulk.requests().get(i)).sourceAsMap();
            assertEquals("splunk_forwarders", ((Map<String, Object>) fullSrc.get("event")).get("module"));
            assertTrue(((Map<String, Object>) fullSrc.get("splunk")).containsKey("s2s"));
            assertEquals(fullSrc.get("message"), src.get("message"));
            assertEquals(((Map<String, Object>) fullSrc.get("splunk")).get("fields"), splunk.get("fields"));
        }
        // switched at runtime: the next bulk has the full set again
        minimal.setMetadata("full");
        Map<String, Object> switched = ((org.elasticsearch.action.index.IndexRequest) minimal.toBulk(docs, S2SIndexer.docIds(docs), 0)
            .requests().get(0)).sourceAsMap();
        assertTrue(((Map<String, Object>) switched.get("splunk")).containsKey("s2s"));
    }

    /** UF running in America/New_York: a negative zone (tag 0x6a) becomes date_zone "-240", as Splunk indexes it. */
    @Test
    @SuppressWarnings("unchecked")
    void negativeZoneFromEdtForwarder() throws Exception {
        for (java.nio.file.Path bin : S2SDecoderTests.bodies(S2SDecoderTests.SAMPLES.resolve("uf-10.4.3-edt"))) {
            for (S2SDecoder.Event e : S2SDecoder.decode(java.nio.file.Files.readAllBytes(bin))) {
                if ("splunkd_conf".equals(e.sourcetype()) && e.structured() && e.raw().length > 0) {
                    EventAssembler asm = new EventAssembler("", 1 << 20);
                    EventAssembler.Doc d = asm.accept("r", java.util.List.of(e), 0).get(0);
                    Map<String, Object> splunk = (Map<String, Object>) S2SIndexer.toSource(d).get("splunk");
                    assertEquals("-240", ((Map<String, Object>) splunk.get("fields")).get("date_zone"));
                    assertTrue(splunk.containsKey("time"));
                    return;
                }
            }
        }
        throw new AssertionError("no splunkd_conf event in the EDT sample");
    }

    /** Raw text: the S2S time is the UF's read time, not Splunk's _time, so no splunk.time. */
    @Test
    @SuppressWarnings("unchecked")
    void noSplunkTimeForUnstructured() throws Exception {
        java.nio.file.Path bin = S2SDecoderTests.bodies(S2SDecoderTests.SAMPLES.resolve("uf-10.4.3-edt")).get(0);
        EventAssembler asm = new EventAssembler("^[ \\t]", 1 << 20);
        java.util.List<EventAssembler.Doc> docs = new java.util.ArrayList<>(asm.accept("r", S2SDecoder.decode(java.nio.file.Files.readAllBytes(bin)), 0));
        docs.addAll(asm.flushAll(0));
        EventAssembler.Doc raw = docs.stream().filter(d -> "loggen:app".equals(d.sourcetype())).findFirst().orElseThrow();
        assertFalse(((Map<String, Object>) S2SIndexer.toSource(raw).get("splunk")).containsKey("time"));
    }

    /** The token's name describes a group of forwarders, so it is splunk.token_name, not agent.name. */
    @Test
    @SuppressWarnings("unchecked")
    void tokenNameIsNotAgentName() {
        RequestInfo req = new RequestInfo("id", 0, "node", "10.0.0.1", null, Map.of(), "fp", 1, 1, 1, 0, "dc1-linux");
        EventAssembler.Doc d = new EventAssembler.Doc("h", "/x.log", "st", "main", "1", 0, null, "m", Map.of(), "10.0.0.1",
            null, req, 0, 1, null, null);
        Map<String, Object> src = S2SIndexer.toSource(d);
        assertEquals("dc1-linux", ((Map<String, Object>) src.get("splunk")).get("token_name"));
        assertFalse(((Map<String, Object>) src.get("agent")).containsKey("name"));
    }

    /** Another token group's event with the same text and position doesn't get this one's id (and so can't suppress it). */
    @Test
    void docIdDependsOnTheToken() {
        EventAssembler.Doc a = at(7, 100, 0, "same line");
        RequestInfo r1 = new RequestInfo("id", 0, "node", "10.0.0.1", null, Map.of(), "aa", 1, 1, 1, 0, null);
        RequestInfo r2 = new RequestInfo("id", 0, "node", "10.0.0.1", null, Map.of(), "bb", 1, 1, 1, 0, null);
        EventAssembler.Doc d1 = new EventAssembler.Doc(a.host(), a.source(), a.sourcetype(), a.index(), null, 0, 0L, a.message(), Map.of(), "",
            a.record(), r1, 0, 1, null, null);
        EventAssembler.Doc d2 = new EventAssembler.Doc(a.host(), a.source(), a.sourcetype(), a.index(), null, 0, 0L, a.message(), Map.of(), "",
            a.record(), r2, 0, 1, null, null);
        assertFalse(S2SIndexer.docId(d1).equals(S2SIndexer.docId(d2)));
        assertEquals(S2SIndexer.docId(d1), S2SIndexer.docId(d1));
    }

    /** A resent request gets the same ids (so it conflicts instead of duplicating); different events never share one. */
    @Test
    void docIdsAreStableAndUnique() throws Exception {
        S2SService svc = new S2SService(org.elasticsearch.common.settings.Settings.builder().put("node.name", "n").build(), null, null);
        java.util.Set<String> seen = new java.util.HashSet<>();
        int events = 0;
        for (String sample : java.util.List.of("uf-10.4.3-edt", "hf-10.4.3")) {
            for (java.nio.file.Path bin : S2SDecoderTests.bodies(S2SDecoderTests.SAMPLES.resolve(sample))) {
                byte[] body = java.nio.file.Files.readAllBytes(bin);
                java.util.List<String> first = S2SIndexer.docIds(svc.decode(body, "r", null, Map.of()));
                assertEquals(first, S2SIndexer.docIds(svc.decode(body, "r", null, Map.of())));
                seen.addAll(first);
                events += first.size();
            }
        }
        // the heavy forwarder's audittrail repeats text within a millisecond, with no file position
        assertTrue(events > 2500, "samples decode to " + events + " events");
        assertEquals(events, seen.size());
    }

    private static EventAssembler.Doc at(long streamId, long offset, long timeMillis, String message) {
        S2SDecoder.Event rec = new S2SDecoder.Event("hf01", "audittrail", "audittrail", null, "_audit", 0x4b, streamId, offset, 0,
            timeMillis, Map.of(), Map.of(), message.getBytes(java.nio.charset.StandardCharsets.UTF_8), -1, List.of(), null, List.of());
        return new EventAssembler.Doc("hf01", "audittrail", "audittrail", "_audit", null, timeMillis, timeMillis, message, Map.of(), "",
            rec, null, 0, 1, null, null);
    }

    /** Text that read from no file (stream 0, offset 0) repeats any day: its time tells it apart. A file position does not need it. */
    @Test
    void docIdsOfEventsFromNoFileUseTheTime() {
        assertFalse(S2SIndexer.docId(at(0, 0, 1_000, "service restarted")).equals(S2SIndexer.docId(at(0, 0, 86_401_000, "service restarted"))));
        // the same line of the same file, read again later (a re-read after a restart): still one event
        assertEquals(S2SIndexer.docId(at(7, 0, 1_000, "first line")), S2SIndexer.docId(at(7, 0, 86_401_000, "first line")));
        assertEquals(S2SIndexer.docId(at(7, 512, 1_000, "a line")), S2SIndexer.docId(at(7, 512, 86_401_000, "a line")));
    }

    /** The same text twice in one request, same time and no position, is two events. */
    @Test
    void repeatsWithinARequestKeepTheirOwnIds() {
        java.util.List<String> ids = S2SIndexer.docIds(java.util.List.of(at(0, 0, 1_000, "x"), at(0, 0, 1_000, "y"), at(0, 0, 1_000, "x")));
        assertEquals(3, new java.util.HashSet<>(ids).size());
        assertEquals(ids, S2SIndexer.docIds(java.util.List.of(at(0, 0, 1_000, "x"), at(0, 0, 1_000, "y"), at(0, 0, 1_000, "x"))));
    }

    /** network.forwarded_ip is an ip field: whatever a proxy writes in X-Forwarded-For must not make every event fail. */
    @Test
    void clientAddressIsAlwaysAnIp() {
        // the last entry is the one the proxy added; a client can send any earlier ones
        assertEquals("203.0.113.10", S2SRestHandler.clientAddress("1.2.3.4, 203.0.113.10", "10.0.0.2"));
        assertEquals("203.0.113.10", S2SRestHandler.clientAddress("203.0.113.10:51234", "10.0.0.2"));
        assertEquals("2001:db8::1", S2SRestHandler.clientAddress("2001:db8::1", "10.0.0.2"));
        assertEquals("2001:db8::1", S2SRestHandler.clientAddress("[2001:db8::1]:51234", "10.0.0.2"));
        assertEquals("10.0.0.2", S2SRestHandler.clientAddress("unknown", "10.0.0.2"));
        assertEquals("10.0.0.2", S2SRestHandler.clientAddress("10.0.0.1, fwd01.corp", "10.0.0.2"));
        assertEquals("10.0.0.2", S2SRestHandler.clientAddress(null, "10.0.0.2"));
        assertEquals("", S2SRestHandler.clientAddress("unknown", null));
    }

    @Test
    void clusterFailuresAreRetriedEventFailuresAreNot() {
        for (RestStatus st : List.of(RestStatus.TOO_MANY_REQUESTS, RestStatus.SERVICE_UNAVAILABLE, RestStatus.UNAUTHORIZED,
            RestStatus.FORBIDDEN, RestStatus.NOT_FOUND)) {
            assertTrue(S2SIndexer.retryable(st), st.toString());
        }
        for (RestStatus st : List.of(RestStatus.BAD_REQUEST, RestStatus.CONFLICT, RestStatus.INTERNAL_SERVER_ERROR)) {
            assertFalse(S2SIndexer.retryable(st), st.toString());
        }
    }
}
