package spring.boot.jwt.recipe.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import spring.boot.jwt.recipe.domain.jwt.JwtTokenProvider;

@Configuration
public class JwtConfig {

    @Bean
    public JwtTokenProvider jwtTokenProvider() {
        return new JwtTokenProvider("jwtRecipeSampleProjectSecretKey!@");
    }

}
