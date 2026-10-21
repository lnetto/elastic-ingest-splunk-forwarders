package co.elastic.s2shttp;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.internal.support.AbstractClient;
import org.elasticsearch.cluster.project.DefaultProjectResolver;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.SecureSettings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.rest.RestStatus;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** When the forwarder is told 200 and when 503, with a client that answers what each test scripts. */
class IndexFlowTests {

    /** Answers key checks from {@link #keyChecks} (true = authenticated as the key) and bulks with {@link #failFirstItem}. */
    static final class FakeClient extends AbstractClient {
        final Deque<Boolean> keyChecks = new ArrayDeque<>();
        final List<BulkRequest> bulks = new ArrayList<>();
        RestStatus failFirstItem;

        FakeClient() {
            super(Settings.EMPTY, null, DefaultProjectResolver.INSTANCE);
        }

        @Override
        @SuppressWarnings("unchecked")
        protected <Req extends ActionRequest, Resp extends ActionResponse> void doExecute(
            ActionType<Resp> action,
            Req request,
            ActionListener<Resp> listener
        ) {
            if (action != KeyCheckAction.TYPE) {
                throw new AssertionError("unexpected " + action.name());
            }
            listener.onResponse((Resp) new KeyCheckAction.Response(keyChecks.removeFirst()));
        }

        /** Not through execute(): TransportBulkAction can't initialize outside a node. */
        @Override
        public void bulk(BulkRequest bulk, ActionListener<BulkResponse> listener) {
            bulks.add(bulk);
            BulkItemResponse[] items = new BulkItemResponse[bulk.numberOfActions()];
            for (int i = 0; i < items.length; i++) {
                String id = bulk.requests().get(i).id();
                items[i] = i == 0 && failFirstItem != null
                    ? BulkItemResponse.failure(i, DocWriteRequest.OpType.CREATE,
                        new BulkItemResponse.Failure("logs-x", id, new IllegalStateException("scripted"), failFirstItem))
                    : BulkItemResponse.success(i, DocWriteRequest.OpType.CREATE, new IndexResponse(new ShardId("logs-x", "_na_", 0), id, i, 1, 1, true));
            }
            listener.onResponse(new BulkResponse(items, 1));
        }
    }

    /** A keystore holding splunk_forwarders.api_key. */
    static Settings withKey(boolean security) {
        SecureSettings secure = new SecureSettings() {
            public boolean isLoaded() { return true; }
            public Set<String> getSettingNames() { return Set.of("splunk_forwarders.api_key"); }
            public SecureString getString(String name) { return new SecureString("a2V5OnNlY3JldA==".toCharArray()); }
            public InputStream getFile(String name) { throw new UnsupportedOperationException(); }
            public byte[] getSHA256Digest(String name) { throw new UnsupportedOperationException(); }
            public void close() {}
            public void writeTo(StreamOutput out) { throw new UnsupportedOperationException(); }
        };
        return Settings.builder().put("xpack.security.enabled", security).setSecureSettings(secure).build();
    }

    static List<EventAssembler.Doc> docs(int n) {
        List<EventAssembler.Doc> docs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            S2SDecoder.Event rec = new S2SDecoder.Event("h", "/x.log", "st", null, "main", 0x23b, 1, i * 10L, i, 0, Map.of(), Map.of(),
                new byte[0], 0, List.of(), null, List.of());
            docs.add(new EventAssembler.Doc("h", "/x.log", "st", "main", null, 0, null, "line " + i, Map.of(), "", rec, null, 0, 1, null, null));
        }
        return docs;
    }

    static S2SIndexer.Result index(FakeClient client, Settings settings, List<EventAssembler.Doc> docs) {
        AtomicReference<S2SIndexer.Result> result = new AtomicReference<>();
        new S2SIndexer(client, new ThreadContext(Settings.EMPTY), settings).indexAsync(docs, ActionListener.wrap(result::set, e -> {
            throw new AssertionError(e);
        }));
        return result.get();
    }

    @Test
    void allIndexedIsSuccess() {
        FakeClient client = new FakeClient();
        S2SIndexer.Result r = index(client, withKey(false), docs(2 * S2SIndexer.SLICE_DOCS + 1));
        assertEquals(new S2SIndexer.Result(2 * S2SIndexer.SLICE_DOCS + 1, 0, false), r);
        assertEquals(3, client.bulks.size());
    }

    /** One 429 item: the forwarder must resend, and no later slice is sent (the resend covers them). */
    @Test
    void backPressureStopsTheBatch() {
        FakeClient client = new FakeClient();
        client.failFirstItem = RestStatus.TOO_MANY_REQUESTS;
        S2SIndexer.Result r = index(client, withKey(false), docs(2 * S2SIndexer.SLICE_DOCS + 1));
        assertTrue(r.retryable());
        assertEquals(1, client.bulks.size());
    }

    /** An item the event itself got wrong (400) is not resent: retrying would fail the same way. */
    @Test
    void eventFailureIsNotResent() {
        FakeClient client = new FakeClient();
        client.failFirstItem = RestStatus.BAD_REQUEST;
        S2SIndexer.Result r = index(client, withKey(false), docs(10));
        assertEquals(new S2SIndexer.Result(9, 1, false), r);
    }

    /** The key is checked before every slice: revoked after the first, nothing more is written as anyone else. */
    @Test
    void keyRevokedMidBatchStopsIt() {
        FakeClient client = new FakeClient();
        client.keyChecks.addAll(List.of(true, false));
        S2SIndexer.Result r = index(client, withKey(true), docs(2 * S2SIndexer.SLICE_DOCS + 1));
        assertTrue(r.retryable());
        assertEquals(S2SIndexer.SLICE_DOCS, r.indexed());
        assertEquals(1, client.bulks.size());
        assertTrue(client.keyChecks.isEmpty());
    }

    /** An empty request (curl, a forwarder's first contact) is only a success if the key works. */
    @Test
    void emptyRequestChecksTheKey() {
        FakeClient client = new FakeClient();
        client.keyChecks.add(false);
        assertTrue(index(client, withKey(true), List.of()).retryable());
        client.keyChecks.add(true);
        assertEquals(new S2SIndexer.Result(0, 0, false), index(client, withKey(true), List.of()));
        assertEquals(0, client.bulks.size());
    }

    @Test
    void noKeyInTheKeystoreIsBusy() {
        FakeClient client = new FakeClient();
        S2SIndexer.Result r = index(client, Settings.EMPTY, docs(1));
        assertTrue(r.retryable());
        assertEquals(0, client.bulks.size());
    }
}
