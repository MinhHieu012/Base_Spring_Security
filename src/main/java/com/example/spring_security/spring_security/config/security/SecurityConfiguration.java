package com.example.spring_security.spring_security.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static com.example.spring_security.spring_security.constant.Role.ADMIN;
import static com.example.spring_security.spring_security.constant.Role.MANAGER;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
@Slf4j
public class SecurityConfiguration {

    // Tạo ra 1 mảng String chứa các đường dẫn API cho phép truy cập mà ko cần quyền (permitAll)
    private static final String[] WHITE_LIST_URL = {
            "/api/v1/auth/**",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/**", // Trỏ tất cả method trong API này
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui/**",
            "/webjars/**",
            "/swagger-ui.html",
            "/api/access/free" // Test
    };

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    /**
     * Cấu hình bộ lọc bảo mật cho ứng dụng
     *
     * @param http Đối tượng HttpSecurity để cấu hình bộ lọc bảo mật
     * @return     Đối tượng SecurityFilterChain chứa các quy tắc bảo mật đã cấu hình
     * @throws     Exception Ngoại lệ xảy ra khi cấu hình bảo mật không hợp lệ
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Tắt bảo mật csrf
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req ->
                        req
                                // API ko cần xác thực -> cho vào
                                .requestMatchers(WHITE_LIST_URL).permitAll()
                                // Yêu cầu có role ADMIN hoặc MANAGER
                                .requestMatchers(GET, "/api/v1/hello/world").hasAnyRole(ADMIN.name(), MANAGER.name())

                                // Test
                                .requestMatchers(GET, "/api/access/admin").hasRole(ADMIN.name())
                                .requestMatchers(GET, "api/access/manager").hasRole(MANAGER.name())

                                // All request đc authenticated => truy cập đc API ko có requestMatchers là mặc định permitAll
                                .anyRequest()
                                .authenticated()
                )
                // Sử dụng chế độ không lưu trữ phiên (Mỗi 1 request riêng biệt)
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

                // Xác thực người dùng trong lần đăng nhập
                .authenticationProvider(authenticationProvider)

                // Thêm bộ lọc xác thực JWT (Mỗi request đều đc điều hướng đến doFilter để kiểm tra)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                // Cấu hình đăng xuất
                .logout(logout ->
                        logout.logoutUrl("/api/v1/auth/logout")
                                // Thêm xử lý đăng xuất
                                .addLogoutHandler(logoutHandler)
                                // Định nghĩa là đăng xuất thành công và xóa bỏ thông tin người dùng trong phiên đăng nhập trong SecurityContextHolder
                                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                )
        ;
        return http.build();
    }
}
