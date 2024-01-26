package space.titcsl.arunaushadhalay.service.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import space.titcsl.arunaushadhalay.exception.InvalidTokenException;
import space.titcsl.arunaushadhalay.service.JwtService;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService{

    @Value("${space.titcsl.arunaushadhalay.jwt_secret_key}")
    private String jwt_secret_key;

    public String generateToken(UserDetails userDetails){
        return  Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 30 * 24 * 60 * 60 * 1000L)) // 30 days in milliseconds
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return  Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1814400000))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaim(token);
        return claimsResolver.apply(claims);
    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    private Claims extractAllClaim(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
        } catch (SecurityException e) {

            throw new InvalidTokenException("We have locked account for internal server security bits exception for securing it more. Please login again! Sorry for inconvenience");
        } catch (Exception e) {

            throw new InvalidTokenException("We have locked account for internal server security bits exception for securing it more. Please login again! Sorry for inconvenience");
        }
    }



    private Key getSignKey() {
       byte[] key = Decoders.BASE64.decode(jwt_secret_key);
       return Keys.hmacShaKeyFor(key);
    }
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    private boolean isTokenExpired(String token){
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}
