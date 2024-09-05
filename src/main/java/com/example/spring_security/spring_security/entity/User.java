package com.example.spring_security.spring_security.entity;

import jakarta.persistence.*;
import lombok.*;
import com.example.spring_security.spring_security.constant.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    // Enum Role đc lưu dưới dạng String
    @Enumerated(EnumType.STRING)
    private Role role;

    // Quan hệ 1-N với Token
    @OneToMany(mappedBy = "user")
    private List<Token> tokens;

    // Lấy danh sách quyền (authority) của người dùng từ Role
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return role.getAuthorities(); }

    @Override
    public String getPassword() { return password; }

    // Tài khoản đăng nhập hiện đang là email
    @Override
    public String getUsername() { return email; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
