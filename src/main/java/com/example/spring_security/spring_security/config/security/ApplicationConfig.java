package com.example.spring_security.spring_security.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.example.spring_security.spring_security.auditing.ApplicationAuditAware;
import com.example.spring_security.spring_security.repository.UserRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;

    /**
     * Cấu hình bean UserDetailsService để lấy thông tin người dùng từ csdl
     *
     * @return Đối tượng UserDetailsService tùy chỉnh
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found!"));
    }

    /**
     * Cấu hình bean AuthenticationProvider để xác thực người dùng
     *
     * @return Đối tượng AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Cấu hình bean AuditorAware để cung cấp thông tin về người dùng hiện tại cho mục đích kiểm toán
     *
     * @return Đối tượng AuditorAware
     */
    @Bean
    public AuditorAware<Integer> auditorAware() { return new ApplicationAuditAware(); }

    /**
     * Cấu hình bean AuthenticationManager để quản lý xác thực
     *
     * @param config Đối tượng AuthenticationConfiguration
     * @return       Đối tượng AuthenticationManager
     * @throws       Exception Ngoại lệ xảy ra nếu cấu hình không hợp lệ
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Cấu hình bean PasswordEncoder để mã hóa mật khẩu
     *
     * @return Đối tượng PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
}
