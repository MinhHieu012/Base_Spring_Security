package com.example.spring_security.spring_security.entity;

import jakarta.persistence.*;
import lombok.*;
import com.example.spring_security.spring_security.constant.TokenType;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Integer id;
    @Column(unique = true)

    public String token;

    @Enumerated(EnumType.STRING)
    public TokenType tokenType = TokenType.BEARER;

    public boolean revoked;

    public boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)

    @JoinColumn(name = "user_id")

    public User user;
}
