package com.ktb.kcmfa.starter;

import org.springframework.beans.factory.ObjectProvider;
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

    /**
     * token ของ user ถูกเก็บใน Redis ระหว่างรอ OTP จึงต้องเข้ารหัสเสมอ (ล้มตอนเริ่มระบบถ้าไม่ตั้งคีย์)
     * ยกเว้นตั้ง kcmfa.redis-allow-plaintext=true โดยเจตนา (ได้ bean เป็น null)
     */
    @Bean
    @ConditionalOnMissingBean
    PayloadCipher kcMfaPayloadCipher(KcMfaProperties props) {
        String key = props.redisEncryptionKey();
        if (key == null || key.isBlank()) {
            if (props.redisAllowPlaintext()) {
                return null;
            }
            throw new IllegalStateException("kcmfa.store=redis requires kcmfa.redis-encryption-key (base64, 32 bytes)"
                    + " because user tokens are kept in Redis; or set kcmfa.redis-allow-plaintext=true to accept plaintext");
        }
        return new PayloadCipher(key);
    }

    @Bean
    @ConditionalOnMissingBean(ChallengeStore.class)
    ChallengeStore kcMfaRedisChallengeStore(StringRedisTemplate redis, KcMfaProperties props,
                                            ObjectProvider<PayloadCipher> cipher) {
        return new RedisChallengeStore(redis, props.redisPrefix(), cipher.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean(OAuthStateStore.class)
    @ConditionalOnProperty(prefix = "kcmfa.oauth", name = "enabled", havingValue = "true")
    OAuthStateStore kcMfaRedisOAuthStateStore(StringRedisTemplate redis, KcMfaProperties props,
                                              ObjectProvider<PayloadCipher> cipher) {
        return new RedisOAuthStateStore(redis, props.redisPrefix(), cipher.getIfAvailable());
    }
}
