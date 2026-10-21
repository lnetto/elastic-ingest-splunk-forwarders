package co.elastic.s2shttp;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;

import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

/**
 * Defines the role {@code splunk_forwarders_anonymous} with no privileges at all. Forwarders send
 * {@code Authorization: Splunk <token>}, which no Elasticsearch realm understands, so they arrive
 * as the anonymous user (xpack.security.authc.anonymous.roles: splunk_forwarders_anonymous) and the plugin
 * checks the token itself. Realms would need yml settings that Elastic Cloud rejects, and custom
 * authenticators are reserved for Elastic's own extensions.
 */
public final class S2SSecurityExtension implements SecurityExtension {

    static final String ANONYMOUS_ROLE = "splunk_forwarders_anonymous";

    private static final RoleDescriptor EMPTY = new RoleDescriptor(ANONYMOUS_ROLE, new String[0], new RoleDescriptor.IndicesPrivileges[0], null);

    @Override
    public String extensionName() {
        return "ingest-splunk-forwarders";
    }

    @Override
    public List<BiConsumer<Set<String>, ActionListener<RoleRetrievalResult>>> getRolesProviders(SecurityComponents components) {
        return List.of((names, listener) -> listener.onResponse(RoleRetrievalResult.success(names.contains(ANONYMOUS_ROLE) ? Set.of(EMPTY) : Set.of())));
    }
}
