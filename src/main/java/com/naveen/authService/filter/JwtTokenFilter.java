package com.naveen.authService.filter;

import com.naveen.authService.service.CustomUserDetailsService;
import com.naveen.authService.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    public JwtTokenFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        logger.info("request: "+request);

        String token = getJwtFromRequest(request);

        if (token != null && jwtUtil.validateToken(token)) {
            String username = jwtUtil.extractUsername(token);

            // Load user details from the database
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Set user authentication
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set the authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);

        logger.info("response: "+response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

