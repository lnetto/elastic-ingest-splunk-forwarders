package co.elastic.s2shttp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.bytes.ReleasableBytesReference;
import org.elasticsearch.common.util.concurrent.AbstractRunnable;
import org.elasticsearch.common.network.InetAddresses;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * {@code POST /services/collector/s2s} on the Elasticsearch HTTP port — the front door for Elastic
 * Cloud, where only the proxied HTTPS endpoint is reachable. The forwarder's {@code Splunk <token>}
 * header is checked against {@code splunk_forwarders.token_sha256}; documents are indexed as the keystore API key
 * {@code splunk_forwarders.api_key}. See {@link S2SSecurityExtension} for how the request gets past ES security.
 */
final class S2SRestHandler implements RestHandler {

    private static final Logger logger = LogManager.getLogger(S2SRestHandler.class);

    private final Supplier<S2SService> service;
    S2SRestHandler(Supplier<S2SService> service) {
        this.service = service;
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(RestRequest.Method.POST, S2SService.S2S_PATH),
            new Route(RestRequest.Method.GET, S2SService.HEALTH_PATH),
            new Route(RestRequest.Method.GET, S2SService.HEALTH_PATH + "/1.0")
        );
    }

    /** The forwarder sends application/octet-stream, which ES would otherwise refuse with 406. */
    @Override
    public boolean mediaTypesValid(RestRequest request) {
        return true;
    }

    @Override
    public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) {
        S2SService svc = service.get();
        if (request.method() == RestRequest.Method.GET) {
            send(channel, S2SService.HEALTHY);
            return;
        }
        // The request arrives as the privilege-less anonymous user: the token is checked here.
        S2SService.Outcome denied = svc.checkToken(request.header("Authorization"));
        if (denied != null) {
            send(channel, denied);
            return;
        }
        ReleasableBytesReference body = request.hasContent() ? request.content() : ReleasableBytesReference.empty();
        // Reserve heap before inflating (the compressed size times a typical ratio), then the decoder
        // resizes it to the inflated size; it is released once the forwarder has its answer.
        MemoryGuard.Reservation memory = svc.memory.reserve();
        long beforeInflate = body.length() + Math.min(S2SDecoder.MAX_INFLATED, body.length() * 6L);
        if (memory.resize(beforeInflate) == false) {
            memory.close();
            send(channel, S2SService.BUSY);
            return;
        }
        // Inflating, decoding and building documents take a while for a large batch: not on the network thread.
        body.mustIncRef();
        try {
            client.threadPool().executor(ThreadPool.Names.WRITE).execute(new AbstractRunnable() {
                @Override
                protected void doRun() {
                    List<EventAssembler.Doc> docs;
                    try {
                        docs = decode(svc, request, body, memory);
                    } finally {
                        body.decRef();
                    }
                    if (docs == null) {
                        memory.close();
                        send(channel, S2SService.BUSY);
                        return;
                    }
                    svc.indexer.indexAsync(docs, ActionListener.releaseAfter(ActionListener.wrap(
                        r -> send(channel, r.retryable() ? S2SService.BUSY : S2SService.SUCCESS),
                        this::onFailure
                    ), memory));
                }

                @Override
                public void onRejection(Exception e) {
                    body.decRef();
                    memory.close();
                    send(channel, S2SService.BUSY); // the write pool is full: the forwarder resends
                }

                @Override
                public void onFailure(Exception e) {
                    memory.close();
                    logger.warn("splunk_forwarders request failed", e);
                    send(channel, new S2SService.Outcome(500, 8, "Internal server error"));
                }
            });
        } catch (RuntimeException e) {
            body.decRef();
            memory.close();
            throw e;
        }
    }

    private static List<EventAssembler.Doc> decode(S2SService svc, RestRequest request, BytesReference body, MemoryGuard.Reservation memory) {
        Map<String, String> headers = new HashMap<>();
        request.getHeaders().forEach((k, v) -> headers.put(k, String.join(", ", v)));
        return svc.decode(body, remote(request), directPeer(request), headers, memory);
    }

    /** Client address; behind the Elastic Cloud proxy that is X-Forwarded-For. */
    private static String remote(RestRequest request) {
        return clientAddress(request.header("X-Forwarded-For"), directPeer(request));
    }

    /**
     * The last X-Forwarded-For entry when it is an IP address (proxies may add a port, or write
     * "unknown"), else the direct peer: it is indexed as network.forwarded_ip, an ip field. The last
     * entry is the one the proxy in front of Elasticsearch added; earlier ones come from the client.
     */
    static String clientAddress(String xff, String peer) {
        if (xff != null && xff.isBlank() == false) {
            String first = xff.substring(xff.lastIndexOf(',') + 1).trim();
            if (first.startsWith("[") && first.indexOf(']') > 0) {
                first = first.substring(1, first.indexOf(']')); // [v6]:port
            } else if (first.indexOf(':') > 0 && first.indexOf(':') == first.lastIndexOf(':')) {
                first = first.substring(0, first.indexOf(':')); // v4:port
            }
            if (InetAddresses.isInetAddress(first)) {
                return first;
            }
        }
        return peer == null ? "" : peer;
    }

    private static String directPeer(RestRequest request) {
        if (request.getHttpChannel() != null && request.getHttpChannel().getRemoteAddress() instanceof InetSocketAddress a) {
            return a.getAddress().getHostAddress();
        }
        return null;
    }

    private static void send(RestChannel channel, S2SService.Outcome o) {
        channel.sendResponse(new RestResponse(RestStatus.fromCode(o.status()), "application/json; charset=UTF-8", o.json()));
    }
}
