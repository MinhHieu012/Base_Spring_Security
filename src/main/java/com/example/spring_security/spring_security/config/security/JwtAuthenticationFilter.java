package com.example.spring_security.spring_security.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.example.spring_security.spring_security.repository.TokenRepository;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    /**
     * Bộ lọc xác thực JWT cho mỗi yêu cầu đến ứng dụng
     *
     * @param request            Đối tượng HttpServletRequest chứa thông tin về yêu cầu
     * @param response           Đối tượng HttpServletResponse để trả về phản hồi
     * @param filterChain        Chuỗi các bộ lọc để tiếp tục xử lý yêu cầu
     * @throws ServletException  Ngoại lệ xảy ra khi xử lý yêu cầu
     * @throws IOException       Ngoại lệ xảy ra khi đọc/ghi dữ liệu
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization"); // Lấy ra header từ request
        final String jwt;
        final String userEmail;

        // Kiểm tra xem header có null hoặc bắt đầu bằng chuỗi Bearer không?
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request,response);
            return;
        }

        // Nếu header tồn tại và đúng định dạng sẽ bỏ qua 7 kí tự đầu tiên
        jwt = authHeader.substring(7); // Cắt chuỗi header từ ký tự index số 7 trở đi ( "Bearer " ) Bearer ... -> Cắt chuỗi là bỏ Bearer
        userEmail = jwtService.extractUsername(jwt); // Lấy ra userEmail từ token

        // Kiểm tra email ko null và trong ContextHolder null?
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            var isTokenValid = tokenRepository.findByToken(jwt) // Tìm token trong db theo chuỗi jwt
                    .map(t -> !t.isExpired() && !t.isRevoked()) // true: 0
                    .orElse(false); // false: 1

            // Kiểm tra xem token có hợp lệ không, nếu hợp lệ lưu vào ContextHolder
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
