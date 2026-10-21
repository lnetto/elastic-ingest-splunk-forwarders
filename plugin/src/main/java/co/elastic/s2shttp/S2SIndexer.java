package co.elastic.s2shttp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestStatus;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Turns assembled events into bulk requests, executed as the configured API key. */
final class S2SIndexer {

    private static final Logger logger = LogManager.getLogger(S2SIndexer.class);

    record Result(int indexed, int failed, boolean retryable) {}

    private static final String NO_KEY = "splunk_forwarders.api_key is not set in the keystore; forwarders get 503 until it is";

    private final Client client;
    private final ThreadContext threadContext;
    private volatile String target;
    private volatile boolean fullMetadata;
    private volatile String authorization;
    private final boolean securityEnabled;
    private volatile long lastKeyWarning;

    S2SIndexer(Client client, ThreadContext threadContext, Settings settings) {
        this.client = client;
        this.threadContext = threadContext;
        this.target = S2SHttpSettings.TARGET.get(settings);
        setMetadata(S2SHttpSettings.METADATA.get(settings));
        this.securityEnabled = settings.getAsBoolean("xpack.security.enabled", true);
        setApiKey(settings);
    }

    /**
     * Reads splunk_forwarders.api_key. Secure settings are only readable while the node starts and during
     * POST _nodes/reload_secure_settings, which calls this again: a new or rotated key needs no restart.
     */
    void setApiKey(Settings settings) {
        try (SecureString key = S2SHttpSettings.API_KEY.exists(settings) ? S2SHttpSettings.API_KEY.get(settings) : null) {
            this.authorization = key == null ? null : "ApiKey " + key;
        }
        if (authorization == null && securityEnabled) {
            logger.warn(NO_KEY);
        }
    }

    void setTarget(String target) {
        this.target = target;
    }

    void setMetadata(String metadata) {
        this.fullMetadata = metadata.equals("full");
    }

    /** Events per bulk request, and their text: a large batch is indexed in slices, one after another. */
    static final int SLICE_DOCS = 2000;
    static final long SLICE_BYTES = 8 * 1024 * 1024;

    /**
     * Bulk as the keystore API key, in slices so that only one slice's documents are built at a time;
     * the result tells the forwarder whether to resend. A slice that must be resent stops the rest: the
     * forwarder resends the whole batch, and what made it is skipped then (same ids). The key is checked
     * before every slice (a large batch takes a minute; the key can be revoked or expire meanwhile) and
     * before answering an empty request, so a forwarder's empty POST tells it the key works.
     */
    void indexAsync(List<EventAssembler.Doc> docs, ActionListener<Result> listener) {
        indexFrom(docs, docIds(docs), 0, new Result(0, 0, false), listener);
    }

    /**
     * Whether a request sent with the keystore API key runs as that key ({@link KeyCheckAction}): a key
     * that is missing or can't be authenticated must not let the bulk run as the internal user.
     */
    private void checkKey(ActionListener<Boolean> listener) {
        if (securityEnabled == false) {
            listener.onResponse(true);
            return;
        }
        String auth = authorization;
        if (auth == null) {
            warnKey(NO_KEY);
            listener.onResponse(false);
            return;
        }
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            threadContext.putHeader("Authorization", auth);
            client.execute(KeyCheckAction.TYPE, new KeyCheckAction.Request(), ActionListener.wrap(r -> {
                if (r.apiKey == false) {
                    warnKey("splunk_forwarders.api_key can't be authenticated (revoked, expired or wrong); forwarders get 503 until "
                        + "a valid key is in the keystore and POST _nodes/reload_secure_settings has run");
                }
                listener.onResponse(r.apiKey);
            }, e -> {
                // refused: only a real identity is refused a cluster:monitor action, and the only one sent is the key
                boolean ok = ExceptionsHelper.status(e) == RestStatus.FORBIDDEN;
                if (ok == false) {
                    warnKey("splunk_forwarders.api_key check failed; forwarders get 503: " + e.getMessage());
                }
                listener.onResponse(ok);
            }));
        }
    }

    private void warnKey(String message) {
        long now = System.currentTimeMillis();
        if (now - lastKeyWarning > 60_000) {
            lastKeyWarning = now;
            logger.warn(message);
        }
    }

    private void indexFrom(List<EventAssembler.Doc> docs, List<String> ids, int from, Result sofar, ActionListener<Result> listener) {
        checkKey(ActionListener.wrap(ok -> {
            if (ok == false) {
                listener.onResponse(new Result(sofar.indexed(), docs.size() - sofar.indexed(), true)); // the forwarder keeps the batch
                return;
            }
            if (from == docs.size()) {
                listener.onResponse(sofar); // an empty request
                return;
            }
            int to = sliceEnd(docs, from);
            bulk(toBulk(docs.subList(from, to), ids.subList(from, to), from), ActionListener.wrap(r -> {
                Result s = summarize(r);
                Result total = new Result(sofar.indexed() + s.indexed(), sofar.failed() + s.failed(), s.retryable());
                if (to == docs.size() || s.retryable()) {
                    listener.onResponse(total);
                } else {
                    indexFrom(docs, ids, to, total, listener);
                }
            }, e -> {
                logger.warn("splunk_forwarders bulk of {} docs failed; forwarder will retry", to - from, e);
                listener.onResponse(new Result(sofar.indexed(), docs.size() - sofar.indexed(), true));
            }));
        }, listener::onFailure));
    }

    /** End (exclusive) of the slice starting at {@code from}: at least one doc. */
    static int sliceEnd(List<EventAssembler.Doc> docs, int from) {
        int to = from;
        long bytes = 0;
        while (to < docs.size() && to - from < SLICE_DOCS && (to == from || bytes < SLICE_BYTES)) {
            String m = docs.get(to).message();
            bytes += m == null ? 0 : m.length();
            to++;
        }
        return to;
    }

    private void bulk(BulkRequest request, ActionListener<BulkResponse> listener) {
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            if (authorization != null) {
                threadContext.putHeader("Authorization", authorization);
            }
            client.bulk(request, listener);
        }
    }

    private Result summarize(BulkResponse resp) {
        int failed = 0;
        boolean retryable = false;
        BulkItemResponse.Failure first = null;
        for (BulkItemResponse item : resp.getItems()) {
            // 409: already indexed by an earlier attempt of this batch (same _id), so it counts as done
            if (item.isFailed() && item.getFailure().getStatus() != RestStatus.CONFLICT) {
                failed++;
                RestStatus st = item.getFailure().getStatus();
                // e.g. the API key cannot write the data stream a pipeline rerouted the doc to: let the UF hold and resend
                if (retryable(st)) {
                    retryable = true;
                }
                if (first == null) {
                    first = item.getFailure();
                }
            }
        }
        if (first != null) {
            logger.warn("splunk_forwarders: {}/{} docs failed, first: [{}] {}", failed, resp.getItems().length, first.getIndex(), first.getMessage());
        }
        return new Result(resp.getItems().length - failed, failed, retryable);
    }

    /**
     * Item failures that are about the cluster, not the event, so the sender should resend: back-pressure,
     * the API key lacking privileges, or the target deleted while the bulk ran (404: the retry recreates the
     * data stream). Anything else is the event's own problem and retrying would fail the same way.
     */
    static boolean retryable(RestStatus st) {
        return st == RestStatus.TOO_MANY_REQUESTS || st == RestStatus.SERVICE_UNAVAILABLE
            || st == RestStatus.UNAUTHORIZED || st == RestStatus.FORBIDDEN || st == RestStatus.NOT_FOUND;
    }

    /** {@code offset}: where {@code docs} starts in its request; the request's first event carries its headers. */
    BulkRequest toBulk(List<EventAssembler.Doc> docs, List<String> ids, int offset) {
        BulkRequest bulk = new BulkRequest();
        boolean full = fullMetadata;
        for (int i = 0; i < docs.size(); i++) {
            EventAssembler.Doc d = docs.get(i);
            bulk.add(new IndexRequest(resolveTarget(d)).id(ids.get(i)).opType(DocWriteRequest.OpType.CREATE).source(toSource(d, offset + i == 0, full)));
        }
        return bulk;
    }

    /**
     * {@link #docId} for each doc of one request. Events without a position in a file (a heavy
     * forwarder's audittrail, for one) can repeat the same text in the same millisecond and still be two
     * events: the second and later copies get their ordinal in the request, which a resend repeats.
     */
    static List<String> docIds(List<EventAssembler.Doc> docs) {
        List<String> ids = new ArrayList<>(docs.size());
        Map<String, Integer> seen = new HashMap<>();
        for (EventAssembler.Doc d : docs) {
            String id = docId(d);
            int n = id == null ? 0 : seen.merge(id, 1, Integer::sum) - 1;
            ids.add(n == 0 ? id : hash(id + "#" + n));
        }
        return ids;
    }

    /**
     * The same id every time the forwarder sends the same event, so a resent batch (after a 503)
     * conflicts on what already made it instead of indexing it twice. Where the event sits in its
     * source (stream, byte offset, sequence, line), plus its text: long lines split into several events
     * share a position. Records without a position fall back to the time: those with none at all, and
     * those that read from no file (stream 0, offset 0: splunkd's stderr, a heavy forwarder's audittrail),
     * whose text can repeat any day. The token is part of it: a sender with another token can't send an
     * event with the same id first and so have this one skipped as already indexed. Error documents get none.
     */
    static String docId(EventAssembler.Doc d) {
        S2SDecoder.Event r = d.record();
        if (r == null) {
            return null;
        }
        boolean inFile = r.offset() > 0 || r.offset() == 0 && r.streamId() != 0;
        String position = inFile ? r.streamId() + ":" + r.offset() + ":" + r.seq() : "t" + d.timeMillis() + ":" + r.seq();
        String token = d.request() == null ? null : d.request().tokenSha256();
        String key = String.join("\0", String.valueOf(token), String.valueOf(d.host()), String.valueOf(d.source()), String.valueOf(d.sourcetype()),
            String.valueOf(d.index()), position, Integer.toString(d.recordLine()), d.message());
        return hash(key);
    }

    private static String hash(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigests.sha256().digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    String resolveTarget(EventAssembler.Doc d) {
        String target = this.target;
        if (target.indexOf('{') < 0) {
            return target;
        }
        return target.replace("{index}", sanitize(d.index())).replace("{sourcetype}", sanitize(d.sourcetype()));
    }

    /** Data stream name parts: lowercase, no '-', no characters ES rejects. */
    static String sanitize(String v) {
        if (v == null || v.isEmpty()) {
            return "unknown";
        }
        String s = NOT_IN_NAME.matcher(v.toLowerCase(Locale.ROOT)).replaceAll("_");
        s = s.startsWith("_") || s.startsWith(".") ? "x" + s : s;
        // a longer name part makes an invalid data stream name and the event is lost; two still fit the 255-byte limit
        return s.length() > MAX_NAME_PART ? s.substring(0, MAX_NAME_PART) : s;
    }

    static final int MAX_NAME_PART = 100;
    private static final Pattern NOT_IN_NAME = Pattern.compile("[^a-z0-9_.]");
    private static final Pattern WINDOWS_PATH = Pattern.compile("^[A-Za-z]:\\\\.*");

    static Map<String, Object> toSource(EventAssembler.Doc d) {
        return toSource(d, true, true);
    }

    static Map<String, Object> toSource(EventAssembler.Doc d, boolean firstInRequest) {
        return toSource(d, firstInRequest, true);
    }

    /**
     * {@code firstInRequest}: the request's headers and the body's timezone record go on its first event
     * only (the others share its splunk.request.id). They are the same for every event of the request,
     * and repeated they made each document several times its text (a 2.5 KB timezone record from any
     * forwarder not on UTC) and indexing that much slower. {@code full}: splunk_forwarders.metadata; minimal leaves out the S2S
     * record, its metadata and the request, though the id ({@link #docId}) is still computed from them.
     */
    static Map<String, Object> toSource(EventAssembler.Doc d, boolean firstInRequest, boolean full) {
        Map<String, Object> src = new HashMap<>();
        src.put("@timestamp", Instant.ofEpochMilli(d.timeMillis()).toString());
        src.put("message", d.message());
        if (d.host() != null) {
            src.put("host", Map.of("name", d.host()));
        }
        if (d.source() != null && d.source().startsWith("/") || d.source() != null && WINDOWS_PATH.matcher(d.source()).matches()) {
            src.put("log", Map.of("file", Map.of("path", d.source())));
        }
        Map<String, Object> splunk = new HashMap<>();
        putIfNotNull(splunk, "index", d.index());
        putIfNotNull(splunk, "host", d.host());
        putIfNotNull(splunk, "source", d.source());
        putIfNotNull(splunk, "sourcetype", d.sourcetype());
        putIfNotNull(splunk, "channel", d.channel());
        if (d.splunkTimeMillis() != null) {
            // Splunk's own _time
            splunk.put("time", Instant.ofEpochMilli(d.splunkTimeMillis()).toString());
        }
        Map<String, Object> fields = new HashMap<>(d.fields());
        S2SDecoder.Event rec = d.record();
        if (rec != null) {
            addDateFields(fields, rec);
        }
        if (fields.isEmpty() == false) {
            splunk.put("fields", fields);
        }
        // which plugin received the event; agent.* is what sent it
        Map<String, Object> event = new HashMap<>();
        event.put("module", "splunk_forwarders");
        if (rec != null && (rec.flags() & S2SDecoder.F_METRIC) != 0) {
            // a metric event (log-to-metrics, _metrics): its measurements are numbers in splunk.fields
            event.put("kind", "metric");
        }
        Map<String, Object> agent = new HashMap<>();
        if (d.request() != null) {
            putIfNotNull(agent, "type", RequestInfo.agentType(d.request().agentBuild()));
        }
        if (full && d.remote() != null && d.remote().isEmpty() == false) {
            src.put("network", Map.of("forwarded_ip", d.remote()));
        }

        // --- everything else the forwarder sent, kept so nothing is lost ---
        if (full && rec != null) {
            if (rec.meta().isEmpty() == false) {
                splunk.put("meta", rec.meta()); // full per-record metadata (_path, _MetaData:Index, ...)
            }
            Map<String, Object> s2s = new HashMap<>();
            s2s.put("flags", rec.flags());
            if (rec.timeSec() >= 0) {
                s2s.put("stream_id", Long.toUnsignedString(rec.streamId()));
                s2s.put("offset", rec.offset());
                s2s.put("seq", rec.seq());
                s2s.put("time", rec.timeSec());
            }
            if (rec.dateParts().isEmpty() == false) {
                List<Map<String, Object>> parts = new ArrayList<>();
                for (S2SDecoder.DatePart p : rec.dateParts()) {
                    parts.add(Map.of("part", p.part(), "name", p.name(), "tag", p.tag(), "value", p.value()));
                }
                s2s.put("date_parts", parts);
            }
            if (rec.csvHeader().isEmpty() == false) {
                s2s.put("csv_header", rec.csvHeader());
            }
            if (rec.timezone() != null && firstInRequest) {
                s2s.put("timezone", rec.timezone());
            }
            s2s.put("structured", rec.structured());
            s2s.put("record_line", d.recordLine());
            s2s.put("record_lines", d.recordLines());
            splunk.put("s2s", s2s);
        }
        RequestInfo r = d.request();
        if (r != null && full == false) {
            putIfNotNull(splunk, "token_name", r.tokenName());
            putIfNotNull(agent, "version", r.agentVersion());
            if (d.bodyBase64() != null) {
                splunk.put("request", Map.of("body_base64", d.bodyBase64())); // the body that couldn't be decoded
            }
        } else if (r != null) {
            Map<String, Object> req = new HashMap<>();
            req.put("id", r.id());
            // which token sent it: the name given in splunk_forwarders.token_sha256 (a group of forwarders, not one
            // agent) and the fingerprint itself, which stays correct if the name changes
            putIfNotNull(splunk, "token_name", r.tokenName());
            putIfNotNull(splunk, "token_sha256", r.tokenSha256());
            req.put("received", Instant.ofEpochMilli(r.receivedMillis()).toString());
            putIfNotNull(req, "node", r.node());
            putIfNotNull(req, "remote_address", r.remoteAddress());
            putIfNotNull(req, "x_forwarded_for", r.xForwardedFor());
            if (firstInRequest) {
                req.put("headers", r.headers());
            }
            req.put("bytes", r.bytes());
            req.put("inflated_bytes", r.inflatedBytes());
            req.put("records", r.records());
            req.put("done_markers", r.doneMarkers());
            putIfNotNull(req, "body_base64", d.bodyBase64());
            splunk.put("request", req);
            putIfNotNull(agent, "version", r.agentVersion());
            if (r.agentBuild() != null) {
                agent.put("build", Map.of("original", r.agentBuild()));
            }
            event.put("ingested", Instant.ofEpochMilli(r.receivedMillis()).toString());
        }
        if (d.error() != null) {
            src.put("error", Map.of("message", d.error(), "type", "s2s_decode"));
            event.put("kind", "pipeline_error");
            if (full) {
                event.put("ingested", Instant.ofEpochMilli(d.timeMillis()).toString());
            }
        }
        src.put("event", event);
        src.put("splunk", splunk);
        src.put("agent", agent);
        return src;
    }

    private static final String[] MONTHS = {
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december" };
    private static final String[] WEEKDAYS = { "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday" };

    /**
     * Timestamp components the forwarder parsed (INDEXED_EXTRACTIONS), under the names and formats
     * Splunk's own index-time fields use, so they match the date_* fields Splunk indexes for the same
     * events: numbers as strings, month/weekday as
     * lowercase names, zone as signed minutes.
     */
    private static void addDateFields(Map<String, Object> fields, S2SDecoder.Event rec) {
        for (S2SDecoder.DatePart p : rec.dateParts()) {
            String name;
            String value;
            switch (p.part()) {
                case 1 -> { name = "date_second"; value = Long.toString(p.value()); }
                case 2 -> { name = "date_minute"; value = Long.toString(p.value()); }
                case 3 -> { name = "date_hour"; value = Long.toString(p.value()); }
                case 4 -> { name = "date_year"; value = Long.toString(p.value()); }
                case 6 -> { name = "date_mday"; value = Long.toString(p.value()); }
                case 5 -> { name = "date_month"; value = pick(MONTHS, p.value() - 16); } // 16 = january
                case 7 -> { name = "date_wday"; value = pick(WEEKDAYS, p.value() - 9); } // 9 = sunday
                // minutes, signed: tag 0x42 (+) or 0x6a (-). Tag 0x4a is the shared constant table
                // (9-15 weekdays, 16-27 months, 28 "local" = TIME_FORMAT without a zone).
                case 8 -> { name = "date_zone"; value = p.tag() == 0x4a ? (p.value() == 28 ? "local" : null) : Long.toString(p.value()); }
                default -> { name = null; value = null; }
            }
            if (name != null && value != null && fields.containsKey(name) == false) {
                fields.put(name, value);
            }
        }
    }

    private static String pick(String[] names, long i) {
        return i >= 0 && i < names.length ? names[(int) i] : null;
    }

    private static void putIfNotNull(Map<String, Object> m, String k, Object v) {
        if (v != null) {
            m.put(k, v);
        }
    }
}
