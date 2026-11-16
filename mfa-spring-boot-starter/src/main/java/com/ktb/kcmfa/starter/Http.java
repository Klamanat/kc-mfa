package com.ktb.kcmfa.starter;

import java.net.http.HttpClient;

import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * สร้าง RestClient ที่มี timeout เสมอ (kcmfa.connect-timeout / kcmfa.read-timeout)
 * เพื่อไม่ให้ Keycloak หรือ MFA service ที่ช้า/ค้างลาก thread ของเว็บค้างตามไปด้วย
 * ใช้ java.net.http.HttpClient (HTTP/1.1) ซึ่งไม่มีปัญหา POST + 401 แบบ HttpURLConnection
 */
final class Http {

    private Http() {}

    static RestClient.Builder builder(KcMfaProperties props) {
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(props.connectTimeout())
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(props.readTimeout());
        return RestClient.builder().requestFactory(factory);
    }

    static RestClient client(KcMfaProperties props) {
        return builder(props).build();
    }
}
