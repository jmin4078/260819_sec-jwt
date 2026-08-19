package org.example.secjwt.auth;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(AuthProperties.class)
public class JwtFilter extends OncePerRequestFilter {
    private final AuthProperties p;
    private final JwtProvider jwtProvider; // claims 해석이 가능

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            // AccessToken -> 2가지 방법으로 저장
            // 1. header
            // 2. cookie
            // -> Header에 들어가 있다 -> request
            String token = extractToken(request);
            Claims claims = jwtProvider.parseClaims(token);
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    claims.getSubject(), // username
                    null,
                    AuthorityUtils.createAuthorityList("ROLE_USER")
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            SecurityContextHolder.clearContext(); // 에러로 인해서 인증 정보 꼬이는 걸 배제
        } finally {
            filterChain.doFilter(request, response);
        }
    }

    private String extractToken(HttpServletRequest request) {
        return null;
    }
}
