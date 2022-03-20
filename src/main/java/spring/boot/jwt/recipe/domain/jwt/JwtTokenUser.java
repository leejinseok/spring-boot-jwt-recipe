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
        this.name = (String) claims.get("name");
        this.email = (String) claims.get("email");
        this.role = (String) claims.get("role");
    }

}
