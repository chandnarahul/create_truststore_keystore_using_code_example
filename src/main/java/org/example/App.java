package org.example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class App {
    public int makeHttpCallTo(String url) throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder().GET().uri(URI.create(url)).build();
        HttpResponse<String> httpResponse = HttpClient.newBuilder().build().send(httpRequest, HttpResponse.BodyHandlers.ofString());
        httpResponse.headers().map().forEach((k, v) -> System.out.println(k + " = " + v));
        System.out.println(httpResponse.statusCode());
        System.out.println(httpResponse.body());
        return httpResponse.statusCode();
    }
}
