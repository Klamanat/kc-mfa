package com.ktb.kcmfa.starter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(KcMfaProperties.class)
public class KcMfaAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    KeycloakClient kcMfaKeycloakClient(KcMfaProperties props) {
        return new KeycloakClient(props);
    }

    @Bean
    @ConditionalOnMissingBean
    ServiceTokenProvider kcMfaServiceTokenProvider(KeycloakClient keycloak) {
        return new ServiceTokenProvider(keycloak);
    }

    @Bean
    @ConditionalOnMissingBean
    MfaServiceClient kcMfaServiceClient(KcMfaProperties props, ServiceTokenProvider tokens) {
        return new MfaServiceClient(props, tokens);
    }

    @Bean
    @ConditionalOnMissingBean(ChallengeStore.class)
    ChallengeStore kcMfaChallengeStore(KcMfaProperties props) {
        requireMemoryStore(props);
        return new InMemoryChallengeStore();
    }

    @Bean
    @ConditionalOnMissingBean
    SessionRevoker kcMfaSessionRevoker(KeycloakClient keycloak, ObjectProvider<ExternalOAuthClient> external) {
        return new SessionRevoker(keycloak, external.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "kcmfa.oauth", name = "enabled", havingValue = "true")
    ExternalOAuthClient kcMfaExternalOAuthClient(KcMfaProperties props) {
        return new ExternalOAuthClient(props);
    }

    @Bean
    @ConditionalOnMissingBean
    ChallengeSweeper kcMfaChallengeSweeper(ChallengeStore store, SessionRevoker revoker, KcMfaProperties props,
                                           ObjectProvider<OAuthLoginFlow> oauth) {
        return new ChallengeSweeper(store, revoker, props.sweepInterval(),
                () -> oauth.ifAvailable(OAuthLoginFlow::sweepExpired));
    }

    @Bean
    @ConditionalOnMissingBean(OAuthStateStore.class)
    @ConditionalOnProperty(prefix = "kcmfa.oauth", name = "enabled", havingValue = "true")
    OAuthStateStore kcMfaOAuthStateStore(KcMfaProperties props) {
        requireMemoryStore(props);
        return new InMemoryOAuthStateStore();
    }

    /** กันกรณีตั้ง kcmfa.store=redis แต่ไม่มี Redis ใน classpath แล้วตกมาใช้ in-memory เงียบๆ */
    private static void requireMemoryStore(KcMfaProperties props) {
        if (!"memory".equalsIgnoreCase(props.store())) {
            throw new IllegalStateException("kcmfa.store=" + props.store()
                    + " but no store bean was created: add spring-boot-starter-data-redis (store=redis)"
                    + " or declare your own ChallengeStore / OAuthStateStore bean");
        }
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "kcmfa.oauth", name = "enabled", havingValue = "true")
    OAuthLoginFlow kcMfaOAuthLoginFlow(ExternalOAuthClient oauth, LoginFlow flow, OAuthStateStore store,
                                       KcMfaProperties props) {
        return new OAuthLoginFlow(oauth, flow, store, props);
    }

    @Bean
    @ConditionalOnExpression("${kcmfa.oauth.enabled:false} and ${kcmfa.controller.enabled:true}")
    KcMfaOAuthController kcMfaOAuthController(OAuthLoginFlow flow, KcMfaProperties props) {
        return new KcMfaOAuthController(flow, props);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginFlow kcMfaLoginFlow(KeycloakClient keycloak, MfaServiceClient mfa, ChallengeStore store, KcMfaProperties props,
                             SessionRevoker revoker) {
        return new LoginFlow(keycloak, mfa, store, props, revoker);
    }

    @Bean
    @ConditionalOnProperty(prefix = "kcmfa.controller", name = "enabled", havingValue = "true", matchIfMissing = true)
    KcMfaAuthController kcMfaAuthController(LoginFlow flow) {
        return new KcMfaAuthController(flow);
    }
}
