package co.elastic.s2shttp;

import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.features.FeatureService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.ClientHelper;
import org.elasticsearch.xpack.core.template.YamlTemplateRegistry;

/**
 * Installs the index template for the default target, logs-splunk.s2s-*, the way Elasticsearch's own
 * inputs (Prometheus remote write, OTLP) do: the elected master puts it, and puts it again when resources.yaml's
 * version goes up. It also installs logs-splunk.s2s@default-pipeline, the streams' default pipeline (set in logs-splunk.s2s@settings),
 * which calls the logs-splunk.s2s@custom ingest pipeline. The template includes logs@custom and logs-splunk.s2s@custom, the
 * component templates that are yours: settings and mappings for these streams go there.
 */
final class S2STemplateRegistry extends YamlTemplateRegistry {

    S2STemplateRegistry(
        Settings nodeSettings,
        ClusterService clusterService,
        ThreadPool threadPool,
        Client client,
        NamedXContentRegistry xContentRegistry,
        FeatureService featureService
    ) {
        super(nodeSettings, clusterService, threadPool, client, xContentRegistry, featureService);
    }

    @Override
    public void initialize() {
        super.initialize();
        clusterService.getClusterSettings().addSettingsUpdateConsumer(S2SHttpSettings.TEMPLATES_ENABLED, this::setEnabled);
    }

    @Override
    protected String getOrigin() {
        return ClientHelper.STACK_ORIGIN;
    }

    @Override
    public String getName() {
        return "ingest-splunk-forwarders";
    }

    @Override
    protected String getVersionProperty() {
        return "splunk_forwarders.template.version";
    }
}
