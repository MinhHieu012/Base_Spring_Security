package com.example.spring_security.spring_security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.spring_security.spring_security.config.security.JwtService;
import com.example.spring_security.spring_security.constant.TokenType;
import com.example.spring_security.spring_security.dto.request.AuthenticationRequest;
import com.example.spring_security.spring_security.dto.request.RegisterRequest;
import com.example.spring_security.spring_security.dto.response.AuthenticationResponse;
import com.example.spring_security.spring_security.entity.Token;
import com.example.spring_security.spring_security.entity.User;
import com.example.spring_security.spring_security.repository.TokenRepository;
import com.example.spring_security.spring_security.repository.UserRepository;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Đăng ký người dùng mới vào hệ thống
     *
     * @param request Đối tượng RegisterRequest chứa thông tin đăng ký
     * @return        Đối tượng AuthenticationResponse chứa token truy cập và token làm mới
     */
    public AuthenticationResponse register(RegisterRequest request) {

        // Tạo đối tượng User mới từ thông tin đăng ký
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        // Lưu đối tượng User vào csdl
        var saveUser = repository.save(user);

        // Tạo token truy cập và token làm mới cho người dùng
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        // Lưu token truy cập vào csdl
        saveUserToken(saveUser, jwtToken);

        // Trả về đối tượng AuthenticationResponse chứa các token
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Xác thực người dùng vào hệ thống
     *
     * @param request Đối tượng AuthenticationRequest chứa thông tin xác thực
     * @return        Đối tượng AuthenticationResponse chứa token truy cập và token làm mới
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // Xác thực thông tin đăng nhập người dùng
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Tìm đối tượng User tương ứng với email
        var user = repository.findByEmail(request.getEmail())
                    .orElseThrow();

        // Tạo token truy cập và token làm mới cho người dùng
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        // Hủy tất cả các token hiện có của người dùng
        revokeAllUserTokens(user);

        // Lưu token truy cập mới vào csdl
        saveUserToken(user, jwtToken);

        // Trả về đối tượng AuthenticationResponse chứa các token
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Lưu token truy cập cho người dùng vào csdl
     *
     * @param user      Đối tượng User
     * @param jwtToken  Token truy cập JWT
     */
    private void saveUserToken(User user, String jwtToken) {
        // Tạo đối tượng Token mới
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        // Lưu đối tượng Token vào csdl
        tokenRepository.save(token);
    }

    /**
     * Hủy tất cả các token hiện có của người dùng
     *
     * @param user Đối tượng User
     */
    private void revokeAllUserTokens(User user) {
        // Tìm tất cả các token hợp lệ của người dùng
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;

        // Đánh dấu các token đó là hết hạn và bị hủy
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        // Lưu các token đã cập nhật vào csdl
        tokenRepository.saveAll(validUserTokens);
    }

    /**
     * Làm mới token truy cập cho người dùng
     *
     * @param request       Đối tượng HttpServletRequest
     * @param response      Đối tượng HttpServletResponse
     * @throws IOException  Ngoại lệ xảy ra khi ghi dữ liệu vào luồng đầu ra
     */
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        // Lấy token làm mới từ header yêu cầu
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);

        // Trích xuất email người dùng từ token làm mới
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            // Kiểm tra tính hợp lệ của token làm mới
            if (jwtService.isTokenValid(refreshToken,user)) {
                /**
                 * Nếu token làm mới hợp lệ
                 * -> Tạo token truy cập mới cho người dùng
                 * -> Hủy tất cả các token hiện có của người dùng
                 * -> Lưu token truy cập mới vào csdl
                 * -> Trả về đối tượng AuthenticationResponse chứa các token mới
                 */
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);

                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
