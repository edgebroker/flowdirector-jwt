package io.edgebroker.flowdirector.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class AuthToken {

    private Algorithm algorithm;
    private String issuer;
    private String token;
    private DecodedJWT decodedJwt;

    public AuthToken(String secret, String issuer) {
        this.algorithm = Algorithm.HMAC256(secret);
        this.issuer = issuer;
    }

    public AuthToken setToken(String token) {
        this.token = token;
        return this;
    }

    private AuthToken decodeJwt() throws Exception {

        if (this.token == null) {
            throw new Exception("Token not set.");
        }

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        this.decodedJwt = verifier.verify(token);

        return this;
    }

    public String fromId(int id) {
        return JWT.create()
                .withClaim("id", id)
                .withIssuer(issuer)
                .sign(algorithm);
    }

    public int getId() throws Exception {

        if (this.decodedJwt == null) {
            throw new Exception("JWT has not been decoded.");
        }

        return decodedJwt.getClaims().get("id").asInt();
    }

    public static void main(String[] args) throws Exception {
        AuthToken authToken = new AuthToken("secret", "flowdirector");

        String token =  authToken.fromId(100);
        System.out.println(token);

        int id = authToken.setToken(token).decodeJwt().getId();
        System.out.println(id);
    }
}
