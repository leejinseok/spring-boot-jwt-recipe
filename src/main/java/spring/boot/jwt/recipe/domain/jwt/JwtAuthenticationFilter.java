package spring.boot.jwt.recipe.domain.jwt;

import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import spring.boot.jwt.recipe.exception.ErrorResponseDto;
import spring.boot.jwt.recipe.exception.JwtTokenIpAddressInvalidException;
import spring.boot.jwt.recipe.utils.Sha256Utils;

@Slf4j
public class JwtAuthenticationFilter extends BasicAuthenticationFilter {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        super(authenticationManager);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        Authentication authentication = null;

        try {
            authentication = getAuthentication(request);
        } catch (ExpiredJwtException | MalformedJwtException e) {
            sendError(response);
            return;
        }

        if (authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private void sendError(HttpServletResponse response) throws IOException {
        response.setStatus(401);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        ErrorResponseDto responseDto = new ErrorResponseDto();
        responseDto.setMessage("토큰 정보가 올바르지 않습니다.");
        String json = new Gson().toJson(responseDto);
        PrintWriter writer = response.getWriter();
        writer.write(json);
        writer.flush();
        writer.close();
    }

    private Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token == null || !token.contains("Bearer")) {
            return null;
        };
        Claims claims = jwtTokenProvider.getClaims(token.substring("Bearer ".length()));
        Set<GrantedAuthority> roles = new HashSet<>();
        String role = String.valueOf(claims.get("role"));
        roles.add(new SimpleGrantedAuthority("ROLE_" + role));
        JwtTokenUser tokenUser = new JwtTokenUser(claims);

        ipValidate(claims, request.getRemoteAddr());
        return new UsernamePasswordAuthenticationToken(tokenUser, null, roles);
    }

    private void ipValidate(Claims claims, String ipAddress) {
        String hash = Sha256Utils.hash(ipAddress);
        if (!claims.get("ipAddress", String.class).equals(hash)) {
            throw new JwtTokenIpAddressInvalidException("IP가 일치하지 않습니다.");
        }
    }
}
