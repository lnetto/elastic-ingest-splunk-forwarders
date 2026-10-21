package co.elastic.s2shttp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.Node;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.LongPredicate;

/** Token check, decoding and event assembly behind the REST endpoint. */
final class S2SService {

    private static final Logger logger = LogManager.getLogger(S2SService.class);

    static final String S2S_PATH = "/services/collector/s2s";
    /** Manual check for this plugin; the HEC plugin (splunk-hec) owns /services/collector/health. */
    static final String HEALTH_PATH = "/services/collector/s2s/health";

    /** HEC-style answer the forwarder understands. */
    record Outcome(int status, int code, String text) {
        String json() {
            return "{\"text\":\"" + text + "\",\"code\":" + code + "}";
        }
    }

    static final Outcome SUCCESS = new Outcome(200, 0, "Success");
    static final Outcome BUSY = new Outcome(503, 9, "Server is busy");
    static final Outcome NO_TOKEN = new Outcome(401, 2, "Token is required");
    static final Outcome BAD_TOKEN = new Outcome(403, 4, "Invalid token");
    static final Outcome HEALTHY = new Outcome(200, 17, "HEC is healthy");

    /** Indented lines continue the previous event (stack traces). */
    static final String CONTINUATION = "^[ \\t]";
    static final int MAX_EVENT_BYTES = 1024 * 1024;
    static final int MAX_ERROR_BODY_BYTES = 10 * 1024 * 1024;

    final S2SIndexer indexer;
    final MemoryGuard memory;
    final TokenRegistry tokens = new TokenRegistry();
    private final String nodeName;

    S2SService(Settings settings, S2SIndexer indexer, MemoryGuard memory) {
        this.indexer = indexer;
        this.memory = memory;
        this.nodeName = Node.NODE_NAME_SETTING.get(settings);
        tokens.set(S2SHttpSettings.TOKEN_SHA256.get(settings));
    }

    /** Null = accepted. An empty allow list rejects everything. */
    Outcome checkToken(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            return NO_TOKEN;
        }
        return tokens.match(token(authorization)) != null ? null : BAD_TOKEN;
    }

    private static LongPredicate room(MemoryGuard.Reservation memory) {
        return memory == null ? bytes -> true : memory::grow;
    }

    static String token(String authorization) {
        return authorization.regionMatches(true, 0, "Splunk ", 0, 7) ? authorization.substring(7).trim() : authorization.trim();
    }

    /**
     * Decode a body and assemble its events, all of them: nothing is held back for a later request, so
     * every event is indexed before the forwarder is answered (it deletes what it was told succeeded).
     * A multi-line event the forwarder split across two requests therefore becomes two events.
     * A body that fails to decode is salvaged: the events before the problem are kept and the body
     * itself becomes an error document, so the forwarder can be answered 200 instead of resending it
     * forever.
     */
    List<EventAssembler.Doc> decode(byte[] body, String remote, String remoteAddress, Map<String, String> headers) {
        return decode(new BytesArray(body), remote, remoteAddress, headers, null);
    }

    /**
     * As above, reading the body in place. With a reservation, its size follows the inflated body
     * ({@link MemoryGuard#PER_INFLATED_BYTE}) and grows with every record and event made from it
     * ({@link S2SDecoder#PER_RECORD}, {@link EventAssembler#PER_EVENT}): a body of tiny events takes far
     * more heap than its size. Null means no room for it: answer busy.
     */
    List<EventAssembler.Doc> decode(BytesReference body, String remote, String remoteAddress, Map<String, String> headers, MemoryGuard.Reservation memory) {
        long now = System.currentTimeMillis();
        S2SDecoder.Batch batch;
        String error = null;
        try {
            byte[] inflated = S2SDecoder.inflate(body);
            if (memory != null && memory.resize(body.length() + (long) MemoryGuard.PER_INFLATED_BYTE * inflated.length) == false) {
                return null;
            }
            batch = S2SDecoder.decodeInflated(inflated, room(memory));
        } catch (S2SDecoder.NoRoom e) {
            return null;
        } catch (S2SDecoder.S2SFormatException e) {
            logger.warn("splunk_forwarders: undecodable payload from {} ({} bytes, {} events recovered): {}", remote, body.length(), e.partialBatch().events().size(), e.getMessage());
            batch = e.partialBatch();
            error = e.getMessage();
        }
        RequestInfo request = RequestInfo.of(nodeName, remoteAddress, headers, body.length(), batch, now, tokens::nameForHash);
        EventAssembler assembler = new EventAssembler(CONTINUATION, MAX_EVENT_BYTES, room(memory));
        List<EventAssembler.Doc> docs;
        try {
            docs = new ArrayList<>(assembler.accept(remote, batch.events(), now, request));
            docs.addAll(assembler.flushAll(now));
        } catch (S2SDecoder.NoRoom e) {
            return null;
        }
        if (error != null) {
            String b64 = body.length() <= MAX_ERROR_BODY_BYTES ? Base64.getEncoder().encodeToString(BytesReference.toBytes(body)) : null;
            docs.add(new EventAssembler.Doc(null, null, null, null, null, now, null,
                "splunk_forwarders: undecodable forwarder payload: " + error, Map.of(), remote, null, request, 0, 0, error, b64));
        }
        return docs;
    }
}
