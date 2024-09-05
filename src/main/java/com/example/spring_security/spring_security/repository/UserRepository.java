package com.example.spring_security.spring_security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.spring_security.spring_security.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);
}