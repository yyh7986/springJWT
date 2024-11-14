package com.example.hellospring.springjwt.repository;

import com.example.hellospring.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {
//    Optional<UserEntity> findByUsername(String username);
    Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
