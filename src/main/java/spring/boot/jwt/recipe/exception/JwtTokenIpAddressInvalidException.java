package spring.boot.jwt.recipe.exception;

public class JwtTokenIpAddressInvalidException extends RuntimeException {

    public JwtTokenIpAddressInvalidException(String message) {
        super(message);
    }

}
