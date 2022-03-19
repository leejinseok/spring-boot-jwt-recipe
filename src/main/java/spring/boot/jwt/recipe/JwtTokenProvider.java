package spring.boot.jwt.recipe;

import io.jsonwebtoken.security.Keys;
import java.security.Key;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtTokenProvider {

    private final Key key;
    public static long PLUS_MILLS = (1000 * 60 * 60 * 24) * 7L;

    public JwtTokenProvider(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

}
