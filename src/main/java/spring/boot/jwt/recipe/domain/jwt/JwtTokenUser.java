package spring.boot.jwt.recipe.domain.jwt;

import io.jsonwebtoken.Claims;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtTokenUser {

    private String name;
    private String email;
    private String role;

    public JwtTokenUser(Claims claims) {
        this.name = claims.get("name", String.class);
        this.email = claims.get("email", String.class);
        this.role = claims.get("role", String.class);
    }

}
