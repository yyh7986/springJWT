package com.example.hellospring.springjwt.controller;

import com.example.hellospring.springjwt.dto.JoinDTO;
import com.example.hellospring.springjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO){
        joinService.JoinProcess(joinDTO);
        return "ok";
    }
}
