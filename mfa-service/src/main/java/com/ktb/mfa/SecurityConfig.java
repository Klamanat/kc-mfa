package com.ktb.mfa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

/** รับเฉพาะ Bearer token จาก issuer (realm) ที่อยู่ใน mfa.trusted-issuers เท่านั้น */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, MfaProps props) throws Exception {
        var resolver = JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(props.trustedIssuers());
        http
                .csrf(csrf -> csrf.disable())   // service-to-service ไม่มี cookie/session
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.authenticationManagerResolver(resolver));
        return http.build();
    }
}
