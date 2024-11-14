package com.example.hellospring.springjwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class RefreshEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;    //하나의 유저가 여러개의 토큰을 발급받을 수 있기 때문에 unique설정은 하지 않는다
    private String refresh;
    private String expiration;
}
