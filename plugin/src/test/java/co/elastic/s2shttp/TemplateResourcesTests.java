package co.elastic.s2shttp;

import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.xcontent.yaml.YamlXContent;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The templates and pipeline resources.yaml names are in the jar, versioned, and match the default target. */
class TemplateResourcesTests {

    static String resource(String path) throws IOException {
        try (InputStream in = S2STemplateRegistry.class.getResourceAsStream(path)) {
            assertNotNull(in, path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void everyListedTemplateIsThereAndVersioned() throws IOException {
        String index = resource("/resources.yaml");
        for (String t : List.of("component-templates/logs-splunk.s2s@mappings", "component-templates/logs-splunk.s2s@settings",
            "index-templates/logs-splunk.s2s@template", "ingest-pipelines/logs-splunk.s2s@default-pipeline")) {
            assertTrue(index.contains(t.substring(t.indexOf('/') + 1)), t);
            assertTrue(resource("/" + t + ".yaml").startsWith("version: ${splunk_forwarders.template.version}"), t);
        }
    }

    @Test
    void templateMatchesTheDefaultTarget() throws IOException {
        String template = resource("/index-templates/logs-splunk.s2s@template.yaml");
        assertTrue(template.contains("index_patterns: [\"logs-splunk.s2s-*\"]"));
        // above 140, so it wins over other templates that overlap logs-splunk.s2s-*
        assertTrue(template.contains("\npriority: 141\n"));
        String target = S2SHttpSettings.TARGET.getDefault(org.elasticsearch.common.settings.Settings.EMPTY);
        assertTrue(target.startsWith("logs-splunk.s2s-"), target);
    }

    /** Indexed fields are one flattened field: however many keys forwarders send, the mapping stays the same size. */
    @Test
    @SuppressWarnings("unchecked")
    void indexedFieldsAreFlattened() throws IOException {
        String yaml = resource("/component-templates/logs-splunk.s2s@mappings.yaml").replace("${splunk_forwarders.template.version}", "1");
        Map<String, Object> m = XContentHelper.convertToMap(YamlXContent.yamlXContent, yaml, false);
        for (String k : List.of("template", "mappings", "properties", "splunk", "properties", "fields")) {
            m = (Map<String, Object>) m.get(k);
            assertNotNull(m, k);
        }
        assertEquals(Map.of("type", "flattened", "ignore_above", 1024), m);
    }

    /** event.module says which plugin received the event: a keyword, whatever dynamic templates the stream has. */
    @Test
    @SuppressWarnings("unchecked")
    void eventModuleIsAKeyword() throws IOException {
        String yaml = resource("/component-templates/logs-splunk.s2s@mappings.yaml").replace("${splunk_forwarders.template.version}", "1");
        Map<String, Object> m = XContentHelper.convertToMap(YamlXContent.yamlXContent, yaml, false);
        for (String k : List.of("template", "mappings", "properties", "event", "properties", "module")) {
            m = (Map<String, Object>) m.get(k);
            assertNotNull(m, k);
        }
        assertEquals(Map.of("type", "keyword"), m);
    }

    @Test
    void defaultPipelineComesBeforeYourCustomTemplate() throws IOException {
        // the plugin's pipeline is the default, and logs-splunk.s2s@custom (later in composed_of) can still replace it
        assertTrue(resource("/component-templates/logs-splunk.s2s@settings.yaml").contains("default_pipeline: logs-splunk.s2s@default-pipeline"));
        String template = resource("/index-templates/logs-splunk.s2s@template.yaml");
        assertTrue(template.indexOf("- logs-splunk.s2s@settings") < template.indexOf("- logs-splunk.s2s@custom"));
        assertTrue(resource("/ingest-pipelines/logs-splunk.s2s@default-pipeline.yaml").contains("name: logs-splunk.s2s@custom\n      ignore_missing_pipeline: true"));
    }
}
