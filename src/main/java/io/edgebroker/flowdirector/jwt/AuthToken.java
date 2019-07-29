package io.edgebroker.flowdirector.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class AuthToken {

    protected static Algorithm algorithm = Algorithm.HMAC256("secret");
    protected static String issuer = "flowdirector";
    DecodedJWT decodedJwt;

    public AuthToken(String token) {
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        this.decodedJwt = verifier.verify(token);
    }

    public static String fromId(int id) {
        return JWT.create()
                .withClaim("id", id)
                .withIssuer(issuer)
                .sign(algorithm);
    }

    public int getId() {
        return decodedJwt.getClaims().get("id").asInt();
    }

    private JWTVerifier createTokenVerifier() {
        return JWT.require(this.algorithm)
                .withIssuer(this.issuer)
                .build();
    }



    public static void main(String[] args) {
        String token =  AuthToken.fromId(100);
        System.out.println(token);
        AuthToken decodedToken = new AuthToken(token);
        System.out.println(decodedToken.getId());
    }
}
