package com.example.hellospring.springjwt.service;

import com.example.hellospring.springjwt.dto.CustomUserDetails;
import com.example.hellospring.springjwt.entity.UserEntity;
import com.example.hellospring.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userData = userRepository.findByUsername(username);

        if(userData != null) {
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
