package spring.boot.jwt.recipe.interfaces.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.boot.jwt.recipe.domain.user.UserDto;

@RestController
public class SessionController {

    @GetMapping("/api/v1/session")
    public UserDto session() {
        return null;
    }

}
