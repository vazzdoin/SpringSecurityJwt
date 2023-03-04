package com.practice.security.jwt.config;

import com.practice.security.jwt.entity.UserInfo;
import com.practice.security.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class  UserInfoUserDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       Optional<UserInfo> userInfo = userRepository.findByName(username);
       return userInfo.map(UserInfoDetails::new)
               .orElseThrow(() -> new UsernameNotFoundException("User not found "));
    }
}
