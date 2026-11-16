package com.ktb.kcmfa.starter;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * kcmfa.store=redis: เก็บ challenge และสถานะ OAuth ใน Redis ของเว็บ (ใช้ StringRedisTemplate ที่ Spring Boot ตั้งค่าจาก spring.data.redis.*)
 * ทำงานก่อน KcMfaAutoConfiguration เพื่อให้ store แบบ in-memory ถอยให้
 */
@AutoConfiguration(before = KcMfaAutoConfiguration.class,
        afterName = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration")
@ConditionalOnClass(StringRedisTemplate.class)
@ConditionalOnProperty(prefix = "kcmfa", name = "store", havingValue = "redis")
@EnableConfigurationProperties(KcMfaProperties.class)
public class KcMfaRedisAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(ChallengeStore.class)
    ChallengeStore kcMfaRedisChallengeStore(StringRedisTemplate redis, KcMfaProperties props) {
        return new RedisChallengeStore(redis, props.redisPrefix());
    }

    @Bean
    @ConditionalOnMissingBean(OAuthStateStore.class)
    @ConditionalOnProperty(prefix = "kcmfa.oauth", name = "enabled", havingValue = "true")
    OAuthStateStore kcMfaRedisOAuthStateStore(StringRedisTemplate redis, KcMfaProperties props) {
        return new RedisOAuthStateStore(redis, props.redisPrefix());
    }
}
