package co.elastic.s2shttp;

import org.elasticsearch.common.settings.SecureSetting;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;

import java.util.List;
import java.util.regex.Pattern;

/** The plugin's settings: where events go, which tokens are allowed, and the key it writes with. */
public final class S2SHttpSettings {

    private S2SHttpSettings() {}

    /** What Elasticsearch accepts as an index or data stream name, once the placeholders are filled in
     * (declared before TARGET, whose default is validated when it is created). */
    private static final Pattern INDEX_NAME = Pattern.compile("[a-z0-9][a-z0-9_.+-]{0,199}");

    /**
     * Target index / data stream; {index} and {sourcetype} are replaced with the Splunk values. The default is
     * one stream: with a placeholder, every value a forwarder sends would create another. The plugin's index
     * template covers logs-splunk.s2s-*, so a placeholder in the namespace (logs-splunk.s2s-{sourcetype}) keeps
     * it; other logs-*-* names get Elasticsearch's built-in logs template.
     */
    public static final Setting<String> TARGET = Setting.simpleString(
        "splunk_forwarders.target",
        "logs-splunk.s2s-default",
        S2SHttpSettings::validateTarget,
        Property.NodeScope,
        Property.Dynamic
    );

    /**
     * Rejects a target no event could be written to: every bulk item would fail without retry, and the
     * forwarder would still be told its events were indexed.
     */
    static void validateTarget(String target) {
        String filled = target.replace("{index}", "x").replace("{sourcetype}", "x");
        if (INDEX_NAME.matcher(filled).matches() == false || filled.equals(".") || filled.equals("..")) {
            throw new IllegalArgumentException("splunk_forwarders.target [" + target + "] is not a valid index or data stream name: "
                + "lowercase letters, digits, '_', '.', '+', '-', not starting with '_', '.', '+' or '-'; placeholders {index} and {sourcetype}");
        }
    }

    /** Allowed tokens as SHA-256 fingerprints, optionally named: "dc1-linux=<sha256 hex>". */
    public static final Setting<List<String>> TOKEN_SHA256 = Setting.stringListSetting(
        "splunk_forwarders.token_sha256",
        Property.NodeScope,
        Property.Dynamic
    );

    /** Encoded Elasticsearch API key the plugin writes with (keystore). */
    public static final Setting<SecureString> API_KEY = SecureSetting.secureString("splunk_forwarders.api_key", null);

    /**
     * What the plugin adds to each event. "minimal": the event (time, text, host, source, sourcetype, index,
     * channel, indexed fields), the token's name and the forwarder's version. "full" adds the S2S record
     * (stream, offset, flags...), its metadata and the request (id, time, node, addresses, headers, sizes),
     * plus event.ingested: as 0.7 did. The document id is the same either way.
     */
    public static final Setting<String> METADATA = new Setting<>(
        "splunk_forwarders.metadata",
        "minimal",
        v -> {
            if (v.equals("full") == false && v.equals("minimal") == false) {
                throw new IllegalArgumentException("splunk_forwarders.metadata must be [full] or [minimal], not [" + v + "]");
            }
            return v;
        },
        Property.NodeScope,
        Property.Dynamic
    );

    /**
     * Whether the elected master installs (and upgrades) the plugin's index template, logs-splunk.s2s-*.
     * Turn it off to manage the template yourself.
     */
    public static final Setting<Boolean> TEMPLATES_ENABLED = Setting.boolSetting(
        "splunk_forwarders.templates.enabled",
        true,
        Property.NodeScope,
        Property.Dynamic
    );

    public static List<Setting<?>> all() {
        return List.of(TARGET, METADATA, TEMPLATES_ENABLED, TOKEN_SHA256, API_KEY);
    }
}
