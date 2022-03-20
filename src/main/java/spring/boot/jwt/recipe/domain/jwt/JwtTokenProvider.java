package spring.boot.jwt.recipe.domain.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import spring.boot.jwt.recipe.domain.user.UserDto;
import spring.boot.jwt.recipe.utils.Sha256Utils;

@Slf4j
public class JwtTokenProvider {

    public static long PLUS_MILLS = (1000 * 60 * 60 * 24) * 7L;

    private final Key key;

    public JwtTokenProvider(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String createToken(UserDto user, String ipAddress){
        String hash = Sha256Utils.hash(ipAddress);
        JwtBuilder builder = Jwts.builder()
            .claim("name", user.getName())
            .claim("role", user.getRole())
            .claim("ipAddress", hash);

        return builder
            .signWith(key, SignatureAlgorithm.HS256)
            .setExpiration(expireTime())
            .compact();
    }

        private Date expireTime() {
        Date expireTime = new Date();
        expireTime.setTime(expireTime.getTime() + PLUS_MILLS);
        return expireTime;
    }

    public Claims getClaims(String token) {
        JwtParser parser = Jwts.parserBuilder()
            .setSigningKey(key)
            .build();
        return parser.parseClaimsJws(token).getBody();
    }

}
