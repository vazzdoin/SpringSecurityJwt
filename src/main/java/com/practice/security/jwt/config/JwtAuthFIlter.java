package com.practice.security.jwt.config;

import com.practice.security.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFIlter extends OncePerRequestFilter {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private JwtService jwtService;


    @Autowired
    UserInfoUserDetailsService userInfoUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        String[] parts = header.split(" ");
        String token = null;
        String username = null;
        if (header != null && header.startsWith("Bearer")) {
            token = parts[1];
            username = jwtService.extractUsername(token);
        }
        logger.info("Checking username");
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userInfoUserDetailsService.loadUserByUsername(username);
            logger.info("UserDetails and validate token : "+userDetails.toString());
            if(jwtService.validateToken(token, userDetails)) {
                logger.info("TOKEN Validated");
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
