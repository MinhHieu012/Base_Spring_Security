package com.example.spring_security.spring_security.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import com.example.spring_security.spring_security.repository.TokenRepository;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    /**
     * Xử lý đăng xuất người dùng khỏi hệ thống
     * Khi người dùng gửi yêu cầu đăng xuất, phương thức này sẽ đc gọi
     *
     * @param request         Đối tượng HttpServletRequest chứa thông tin yêu cầu về đăng xuất
     * @param response        Đối tượng HttpServletResponse dùng để trả về phản hồi cho yêu cầu
     * @param authentication  Đối tượng Authentication chứa thông tin xác thực của người dùng
     */
    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization"); // Lấy gía trị của header "Authorization" từ yêu cầu
        final String jwt;

        // Kiểm tra nếu header không tồn tại hoặc ko bắt đầu bằng chuối "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            return;
        }

        // Nếu header tồn tại và đúng định dạng -> lấy chuỗi JWT từ sau cụm "Bearer "
        jwt = authHeader.substring(7);

        // Tìm token trong csdl dựa trên chuỗi JWT
        var storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);

        // Nếu token tồn tại trong csdl
        if (storedToken != null) {
            // Đánh dấu token đã hết hạn
            storedToken.setExpired(true);

            // Đánh dấu token đã bị thu hồi
            storedToken.setRevoked(true);

            // Lưu lại trạng thái mới của token vào csdl
            tokenRepository.save(storedToken);

            // Xóa thông tin xác thực khỏi SecurityContextHolder
            SecurityContextHolder.clearContext();
        }
    }
}
