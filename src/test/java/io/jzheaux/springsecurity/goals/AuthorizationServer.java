package io.jzheaux.springsecurity.goals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.Buffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class AuthorizationServer extends Dispatcher implements AutoCloseable {
    private static final String ISSUER_PATH = "/oauth2";
    private static final String CONFIGURATION_PATH = "/.well-known/openid-configuration";
    private static final String JWKS_PATH = "/jwks";
    private static final String INTROSPECTION_PATH = "/introspect";

    private static final MockResponse NOT_FOUND_RESPONSE = response(
            "{ \"message\" : \"This mock authorization server responds only to [" +
                    ISSUER_PATH + CONFIGURATION_PATH + "," + ISSUER_PATH + JWKS_PATH + "," + ISSUER_PATH + INTROSPECTION_PATH + "]\" }",
            404
    );

    private final RSAKey key;
    private Map<String, JWT> tokens = new HashMap<>();
    private Map<String, Function<RecordedRequest, MockResponse>> responses = new HashMap<>();
    private MockWebServer web = new MockWebServer();
    private ObjectMapper mapper = new ObjectMapper();

    AuthorizationServer() {
        try {
            this.key = new RSAKeyGenerator(2048).keyID("one").generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String configuration = ISSUER_PATH + CONFIGURATION_PATH;
        String jwks = ISSUER_PATH + JWKS_PATH;
        String introspection = ISSUER_PATH + INTROSPECTION_PATH;
        this.responses.put(configuration, request -> {
            String issuer = issuer();
            Map<String, String> metadata = new LinkedHashMap<>();
            metadata.put("issuer", issuer);
            metadata.put("jwks_uri", issuer + JWKS_PATH);
            return response(new JSONObject(metadata).toString(), 200);
        });
        this.responses.put(jwks, request -> response(new JWKSet(this.key).toString(), 200));
        this.responses.put(introspection, request ->
                Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
                        .filter(authorization -> isAuthorized(authorization, "app", "bfbd9f62-02ce-4638-a370-80d45514bd0a"))
                        .map(authorization -> parseBody(request.getBody()))
                        .map(parameters -> parameters.get("token"))
                        .map(this.tokens::get)
                        .filter(this::isActive)
                        .map(this::withActive)
                        .map(jsonObject -> response(jsonObject, 200))
                        .orElse(response(new JSONObject(Collections.singletonMap("active", false)).toString(), 200))
        );
    }

    public MockResponse dispatch(RecordedRequest recordedRequest) {
        String path = recordedRequest.getPath();
        return Optional.ofNullable(this.responses.get(path))
                .map(function -> function.apply(recordedRequest))
                .orElse(NOT_FOUND_RESPONSE);
    }

    void start() throws IOException {
        this.web.setDispatcher(this);
        this.web.start();
    }

    void stop() throws IOException {
        this.web.shutdown();
    }

    @Override
    public void close() throws Exception {
        stop();
    }

    JWT tokenFor(String username) {
        try {
            for (JWT jwt : this.tokens.values()) {
                JWTClaimsSet claims = jwt.getJWTClaimsSet();
                if (username.equals(claims.getSubject())) {
                    return jwt;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    String token(String username, String... scope) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID("one").build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer(issuer())
                .claim("scope", Stream.of(scope).collect(Collectors.joining(" ")))
                .build();
        SignedJWT jws = new SignedJWT(header, claims);
        try {
            jws.sign(new RSASSASigner(this.key));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.tokens.put(jws.serialize(), jws);
        return jws.serialize();
    }

    void revoke(String token) {
        this.tokens.remove(token);
    }

    String issuer() {
        return this.web.url(ISSUER_PATH).toString();
    }

    String jwkSetUri() {
        return this.web.url(ISSUER_PATH + JWKS_PATH).toString();
    }

    String introspectionUri() {
        return this.web.url(ISSUER_PATH + INTROSPECTION_PATH).toString();
    }

    private boolean isAuthorized(String authorization, String username, String password) {
        String[] values = new String(Base64.getDecoder().decode(authorization.substring(6))).split(":");
        return username.equals(values[0]) && password.equals(values[1]);
    }

    private Map<String, Object> parseBody(Buffer body) {
        return Stream.of(body.readUtf8().split("&"))
                .map(parameter -> parameter.split("="))
                .collect(Collectors.toMap(parts -> parts[0], parts -> parts[1]));
    }

    private boolean isActive(JWT jwt) {
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date now = new Date();
            return (claims.getIssueTime() == null || claims.getIssueTime().before(now)) &&
                    (claims.getExpirationTime() == null || claims.getExpirationTime().after(now)) &&
                    (claims.getNotBeforeTime() == null || claims.getNotBeforeTime().before(now));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String withActive(JWT jwt) {
        try {
            Map<String, Object> claims = jwt.getJWTClaimsSet().toJSONObject();
            claims.put("active", true);
            return this.mapper.writeValueAsString(claims);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static MockResponse response(String body, int status) {
        return new MockResponse()
                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .setResponseCode(status)
                .setBody(body);
    }
}
