package store.auth;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import store.account.AccountOut;

@Service
public class JwtService {

    @Value("${store.jwt.secretKey}")
    private String secretKey;

    public String generate(AccountOut account, long duration) {

        Date now = new Date();

        String jwt = Jwts.builder()
            .header()
            .and()
            .id(account.id())
            .issuer("Insper::PMA")
            .claims(Map.of(
                "email", account.email()
            ))
            .signWith(getKey())
            .subject(account.name())
            .notBefore(now)
            .expiration(new Date(now.getTime() + duration)) // in miliseconds
            .compact();
        return jwt;

    }

    public String getId(String jwt) {
        // constroe o parser
        JwtParser parser = Jwts.parser().verifyWith(getKey()).build();
        // recupero os atributos
        Claims claims = parser.parseSignedClaims(jwt).getPayload();
        Date now = new Date();
        if (claims.getNotBefore().after(now)) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Token is not valid yet!"
            );
        }
        if (claims.getExpiration().before(now)) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Token is expired!"
            );
        }
        return claims.getId();
    }

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }
    
}
