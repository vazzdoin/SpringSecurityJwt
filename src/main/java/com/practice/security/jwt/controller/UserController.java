package com.practice.security.jwt.controller;

import com.practice.security.jwt.dto.AuthRequest;
import com.practice.security.jwt.entity.UserInfo;
import com.practice.security.jwt.service.JwtService;
import com.practice.security.jwt.service.UserUtilService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserUtilService userUtilService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String getUsers() {
        return "Users received";
    }

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome to the app";
    }

    @GetMapping("/specific")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String random() {
        return "Authority specific";
    }

    @PostMapping("/add")
    public ResponseEntity<UserInfo> create(@RequestBody UserInfo userInfo) {
        return userUtilService.create(userInfo);
    }

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getName(), authRequest.getPassword()));
        if(authentication.isAuthenticated()) {
            return jwtService.generateToken(authRequest.getName());
        } else {
            throw new UsernameNotFoundException("Invalid User Request !");
        }
    }

}
