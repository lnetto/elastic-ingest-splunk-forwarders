package co.elastic.s2shttp;

import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.user.User;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyCheckActionTests {

    @Test
    void onlyAnApiKeyPasses() {
        User keyOwner = new User("splunk-forwarders-owner");
        Authentication apiKey = Authentication.newApiKeyAuthentication(AuthenticationResult.success(keyOwner, Map.of(
            "_security_api_key_id", "id1",
            "_security_api_key_name", "splunk-forwarders",
            "_security_api_key_type", "rest",
            "_security_api_key_creator_realm_name", "native",
            "_security_api_key_creator_realm_type", "native")), "node");
        Authentication user = Authentication.newRealmAuthentication(keyOwner, new Authentication.RealmRef("native", "native", "node"));
        assertTrue(KeyCheckAction.isApiKey(apiKey));
        assertFalse(KeyCheckAction.isApiKey(user));                     // a user, or the internal user a bad key falls back to
        assertFalse(KeyCheckAction.isApiKey(null));                     // no authentication at all (security off)
        assertFalse(KeyCheckAction.isApiKey("not an authentication"));
    }
}
