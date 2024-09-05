package com.example.spring_security.spring_security.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {
    /**
     * Khóa bí mật đc sử dụng để tạo và xác minh chữ ký của JWT
     * Giá trị của khóa này được lấy từ biến môi trường
     */
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    /**
     * Thời gian hết hạn của access token JWT (ms)
     * Giá trị này được lấy từ biến môi trường
     */
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    /**
     * Thời gian hết hạn của refresh token JWT (ms)
     * Giá trị này được lấy từ biến môi trường
     */
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    /**
     * Trích xuất tên người dùng từ JWT Token
     * @param token JWT Token
     * @return Tên người dùng
     */
    public String extractUsername(String token) { return extractClaim(token, Claims::getSubject); }

    /**
     * Trích xuất 1 claim cụ thể từ JWT Token
     *
     * @param token           JWT Token
     * @param claimsResolver  Hàm lambda để trích xuất claim từ đối tượng Claims
     * @param <T>             Kiểu dữ liệu của claim
     * @return                Giá trị của claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Tạo ra 1 access token JWT mới cho người dùng
     * @param userDetails Thông tin của người dùng
     * @return            Access Token JWT
     */
    public String generateToken(UserDetails userDetails) { return generateToken(new HashMap<>(), userDetails); }

    /**
     * Tạo 1 access token JWT mới cho người dùng với các claim bổ sung
     *
     * @param extraClaims Các claim bổ sung
     * @param userDetails Thông tin của người dùng
     * @return Access token của JWT
     */
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Tạo 1 refresh token JWT mới cho người dùng
     * @param userDetails Thông tin của người dùng
     * @return Refresh token JWT
     */
    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    /**
     * Tạo 1 JWT token mới với các claim và thời gian hết hạn được chỉ định
     *
     * @param extraClaims Các claim bổ sung
     * @param userDetails Thông tin của người dùng
     * @param expiration  Thời gian hết hạn của token (ms)
     * @return            JWT Token
     */
    private String buildToken(
            Map<String, Object> extraClaims, // Đối tượng map
            UserDetails userDetails, // Đối tượng userDetails
            long expiration // Thời gian tồn tại token
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims) // Khởi tạo 1 object payload
                // Thêm các giá trị vào payload
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Thêm chữ ký và thuật toán dùng cho token
                .compact(); // Tạo ra token
    }

    /**
     * Kiểm tra tính hợp lệ của JWT Token dựa trên tên người dùng và thời gian hết hạn
     *
     * @param token        JWT Token
     * @param userDetails  Thông tin người dùng
     * @return             True nếu token hợp lệ, false nếu không
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Kiểm tra xem JWT token đã hết hạn hay chưa
     *
     * @param token JWT token
     * @return      True nếu token hết hạn, false nếu còn hạn
     */
    private boolean isTokenExpired(String token) { return extractExpiration(token).before(new Date()); }

    /**
     * Trích xuất thời gian hết hạn từ JWT Token
     *
     * @param token JWT token
     * @return      Thời gian hết hạn của token
     */
    private Date extractExpiration(String token) { return extractClaim(token, Claims::getExpiration); }

    /**
     * Trích xuất tất cả các claim (claims) từ JWT Token
     *
     * @param token JWT token
     * @return      Đối tượng Claims chứa các claim
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Tạo khóa ký cho JWT token từ khóa bí mật (secret-key)
     *
     * @return Khoó ký cho JWT token
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
