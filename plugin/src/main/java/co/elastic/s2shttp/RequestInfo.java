package co.elastic.s2shttp;

import org.elasticsearch.common.hash.MessageDigests;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.UnaryOperator;

/**
 * Everything known about one forwarder HTTP request, stamped on every document it produces so
 * nothing the forwarder sent is lost (headers, sizes, where it came in). Never holds credentials:
 * the HEC token is kept only as a SHA-256 fingerprint and credential-bearing headers are dropped.
 */
record RequestInfo(
    String id,
    long receivedMillis,
    String node,
    String remoteAddress, // direct TCP peer (on Elastic Cloud: the proxy)
    String xForwardedFor, // full chain as received, or null
    Map<String, String> headers, // lower-cased names, credential headers removed
    String tokenSha256, // fingerprint of the HEC token, or null
    int bytes, // compressed body
    int inflatedBytes,
    int records,
    int doneMarkers,
    String tokenName // name given to the token in splunk_forwarders.token_sha256, or null
) {

    /** {@code tokenNames}: the name for a token fingerprint ({@link TokenRegistry#nameForHash}). */
    static RequestInfo of(
        String node,
        String remoteAddress,
        Map<String, String> rawHeaders,
        int bodyBytes,
        S2SDecoder.Batch batch,
        long now,
        UnaryOperator<String> tokenNames
    ) {
        Map<String, String> headers = new TreeMap<>();
        String token = null;
        for (Map.Entry<String, String> h : rawHeaders.entrySet()) {
            String name = h.getKey().toLowerCase(Locale.ROOT);
            if (name.equals("authorization")) {
                token = h.getValue() == null ? null : S2SService.token(h.getValue()); // as the token check reads it
                continue;
            }
            if (isCredential(name)) {
                continue;
            }
            headers.put(name, h.getValue());
        }
        String sha = token == null || token.isEmpty() ? null : sha256(token);
        return new RequestInfo(
            UUID.randomUUID().toString(),
            now,
            node,
            remoteAddress,
            headers.get("x-forwarded-for"),
            headers,
            sha,
            bodyBytes,
            batch.inflatedBytes(),
            batch.events().size(),
            batch.doneMarkers(),
            sha == null ? null : tokenNames.apply(sha)
        );
    }

    /** Headers that can carry a token, password or session: never stored. */
    static boolean isCredential(String lowerName) {
        return lowerName.equals("proxy-authorization")
            || lowerName.equals("cookie")
            || lowerName.equals("set-cookie")
            || lowerName.contains("token")
            || lowerName.contains("secret")
            || lowerName.contains("password")
            || lowerName.contains("api-key")
            || lowerName.contains("apikey");
    }

    /** "splunkforwarder-10.4.3-4174a2deda5d" -> "10.4.3". */
    String agentVersion() {
        String v = headers.get("__splunk_app_version");
        if (v == null) {
            return null;
        }
        String[] parts = v.split("-");
        return parts.length >= 2 ? parts[1] : v;
    }

    /** The forwarder's build as sent: "splunkforwarder-10.4.3-4174a2deda5d", "splunk-10.6.0.5-86587d4e3b27". */
    String agentBuild() {
        return headers.get("__splunk_app_version");
    }

    /**
     * The sender's product as Splunk names it, the build up to its first "-": "splunkforwarder" (universal
     * forwarder) or "splunk" (Splunk Enterprise, a heavy forwarder). Null without a build.
     */
    static String agentType(String build) {
        if (build == null) {
            return null;
        }
        int dash = build.indexOf('-');
        String type = dash < 0 ? build : build.substring(0, dash);
        return type.isEmpty() ? null : type;
    }

    static String sha256(String s) {
        return MessageDigests.toHexString(MessageDigests.sha256().digest(s.getBytes(StandardCharsets.UTF_8)));
    }
}
