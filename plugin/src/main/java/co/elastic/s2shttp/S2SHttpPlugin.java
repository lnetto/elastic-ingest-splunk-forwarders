package co.elastic.s2shttp;

import org.apache.lucene.util.SetOnce;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.features.NodeFeature;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.ReloadablePlugin;
import org.elasticsearch.rest.RestHandler;

import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Receives Splunk Universal Forwarder {@code [httpout]} traffic (S2S over HTTP) on the
 * Elasticsearch HTTP port, {@code POST /services/collector/s2s}, and indexes the events.
 */
public class S2SHttpPlugin extends Plugin implements ActionPlugin, ReloadablePlugin {

    private final SetOnce<S2SService> service = new SetOnce<>();
    private final SetOnce<S2SIndexer> indexer = new SetOnce<>();
    private final SetOnce<S2STemplateRegistry> templates = new SetOnce<>();

    @Override
    public List<Setting<?>> getSettings() {
        return S2SHttpSettings.all();
    }

    @Override
    public Collection<?> createComponents(PluginServices services) {
        Settings settings = services.environment().settings();
        S2SIndexer indexer = new S2SIndexer(services.client(), services.threadPool().getThreadContext(), settings);
        MemoryGuard memory = MemoryGuard.forHeap(services.indicesService().getCircuitBreakerService().getBreaker(CircuitBreaker.REQUEST));
        S2SService svc = new S2SService(settings, indexer, memory);
        ClusterSettings cs = services.clusterService().getClusterSettings();
        cs.addSettingsUpdateConsumer(S2SHttpSettings.TARGET, indexer::setTarget);
        cs.addSettingsUpdateConsumer(S2SHttpSettings.METADATA, indexer::setMetadata);
        cs.addSettingsUpdateConsumer(S2SHttpSettings.TOKEN_SHA256, svc.tokens::set, TokenRegistry::validate);
        this.indexer.set(indexer);
        service.set(svc);
        S2STemplateRegistry registry = new S2STemplateRegistry(settings, services.clusterService(), services.threadPool(),
            services.client(), services.xContentRegistry(), services.featureService());
        registry.setEnabled(S2SHttpSettings.TEMPLATES_ENABLED.get(settings));
        registry.initialize();
        templates.set(registry);
        return List.of();
    }

    @Override
    public void close() {
        if (templates.get() != null) {
            templates.get().close();
        }
    }

    @Override
    public Collection<RestHandler> getRestHandlers(
        RestHandlersServices restHandlersServices,
        Supplier<DiscoveryNodes> nodesInCluster,
        Predicate<NodeFeature> clusterSupportsFeature
    ) {
        return List.of(new S2SRestHandler(service::get));
    }

    @Override
    public Collection<ActionHandler> getActions() {
        return List.of(new ActionHandler(KeyCheckAction.TYPE, KeyCheckAction.class));
    }

    /** POST _nodes/reload_secure_settings: picks up a new or rotated splunk_forwarders.api_key without a restart. */
    @Override
    public void reload(Settings settings) {
        S2SIndexer ix = indexer.get();
        if (ix != null) {
            ix.setApiKey(settings);
        }
    }
}
