package de.morihofi.jwttest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;

public class Main {


    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());



        System.out.println("---- GENERATE KEY ----");
        byte[] hmacKey = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(hmacKey);
        Key signingKey = new SecretKeySpec(hmacKey, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        mac.init(signingKey);

        JSONObject payloadObj = new JSONObject();
        payloadObj.put("session","123456");

        Algorithm algorithm = Algorithm.HMAC256(hmacKey);
        String token = null;

        System.out.println("HMAC-Key (base64): " + Base64.toBase64String(hmacKey));
        System.out.println("(Note: Check 'secret base64 encoded' on https://jwt.io/, then paste in key and then paste token)");

        // Generation ends here

        try {

            // Create JWT
            token = JWT.create()
                    .withIssuer("morihofi")
                    //Token should expire in 60 seconds
                    .withExpiresAt(Instant.now().plusSeconds(60))
                    .withNotBefore(Instant.now())
                    .withPayload(payloadObj.toString())
                    .sign(algorithm);
            System.out.println("Token: " + token);



        } catch (JWTCreationException exception){
            // Invalid Signing configuration / Couldn't convert Claims.
            exception.printStackTrace();
        }

        //Verify previously generated token
        System.out.println("---- VERIFY ----");
        try {
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(token);
            // Token is valid, now you can use the decoded JWT Token
            System.out.println("Token is valid!");
            System.out.println("Issuer: " + decodedJWT.getIssuer());
            System.out.println("Expires at: " + decodedJWT.getExpiresAt());
            System.out.println("Not Before: " + decodedJWT.getNotBefore());
            System.out.println("Payload (base64): " + decodedJWT.getPayload());
        } catch (JWTVerificationException e) {
            // Token is invalid or couldn't be checked
            System.out.println("Token is invalid!");
            e.printStackTrace();
            
        }
    }
}