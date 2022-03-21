package spring.boot.jwt.recipe.interfaces;

import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.boot.jwt.recipe.domain.jwt.JwtTokenProvider;
import spring.boot.jwt.recipe.domain.user.UserDto;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;

    @GetMapping("/api/v1/auth/login")
    public String login(HttpServletRequest servletRequest) {
        UserDto userDto = new UserDto();
        userDto.setEmail("sonaky47@gmail.com");
        userDto.setName("이진석");
        userDto.setRole("USER");
        return jwtTokenProvider.createToken(userDto, servletRequest.getRemoteAddr());
    }

}
