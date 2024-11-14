package com.example.hellospring.springjwt.service;

import com.example.hellospring.springjwt.dto.JoinDTO;
import com.example.hellospring.springjwt.entity.UserEntity;
import com.example.hellospring.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public void JoinProcess(JoinDTO joinDTO){
        String username=joinDTO.getUsername();
        String password=joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);
        if(isExist){
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(passwordEncoder.encode(password));
        data.setRole("ADMIN");

        userRepository.save(data);

        /*if(userRepository.findByUsername(joinDTO.getUsername()).isEmpty()){
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setPassword(password);
            userEntity.setRole("USER");
            userRepository.save(userEntity);
        };*/
    }
}
