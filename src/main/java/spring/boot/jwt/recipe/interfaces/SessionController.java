package spring.boot.jwt.recipe.interfaces;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.boot.jwt.recipe.domain.jwt.JwtTokenUser;
import spring.boot.jwt.recipe.domain.user.UserDto;

@RestController
public class SessionController {

    @GetMapping("/api/v1/session")
    public UserDto session(@AuthenticationPrincipal JwtTokenUser jwtTokenUser) {
        return null;
    }

}
