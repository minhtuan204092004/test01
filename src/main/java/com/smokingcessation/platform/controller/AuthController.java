package com.smokingcessation.platform.controller;

//import com.smokingcessation.platform.model.LoginRequest;
//import com.smokingcessation.platform.model.LoginResponse;
//import com.smokingcessation.platform.service.AuthService;
//import io.swagger.v3.oas.annotations.Operation;
//import io.swagger.v3.oas.annotations.responses.ApiResponse;
//import io.swagger.v3.oas.annotations.responses.ApiResponses;
//import io.swagger.v3.oas.annotations.tags.Tag;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//@RestController
//@RequestMapping("/api/auth")
//@RequiredArgsConstructor
//@CrossOrigin(origins = "*")
//@Tag(name = "Authentication", description = "APIs for authentication")
//public class AuthController {
//
//    private final AuthService authService;
//
//    @Operation(summary = "Login to system", description = "Login with username and password")
//    @ApiResponses(value = {
//        @ApiResponse(responseCode = "200", description = "Login successful"),
//        @ApiResponse(responseCode = "401", description = "Invalid username or password"),
//        @ApiResponse(responseCode = "403", description = "Account is not active")
//    })
//    @PostMapping("/login")
//    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
//        try {
//            LoginResponse response = authService.login(request);
//            return ResponseEntity.ok(response);
//        } catch (RuntimeException e) {
//            if (e.getMessage().contains("not active")) {
//                return ResponseEntity.status(403).build();
//            }
//            return ResponseEntity.status(401).build();
//        }
//    }
//}

import com.smokingcessation.platform.entity.User;
import com.smokingcessation.platform.model.LoginRequest;
import com.smokingcessation.platform.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtTokenProvider.generateToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            return ResponseEntity.ok(new JwtResponse(
                    jwt,
                    userDetails.getId(),
                    userDetails.getEmail(),
                    userDetails.getUsername(),
                    userDetails.getAuthorities()
            ));

        } catch (AuthenticationException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Email hoặc mật khẩu không đúng"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        // Validate email format
        if (!isValidEmail(request.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Email không hợp lệ"));
        }

        // Check if email exists
        if (userService.existsByEmail(request.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Email đã được sử dụng"));
        }

        // Check if username exists
        if (userService.existsByUsername(request.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Username đã được sử dụng"));
        }

        // Create new user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFullName(request.getFullName());
        user.setPhone(request.getPhone());
        user.setGender(request.getGender());
        user.setAge(request.getAge());
        user.setStatus(User.UserStatus.PENDING);

        Set<Role.RoleName> roles = Set.of(Role.RoleName.ROLE_USER);
        user = userService.registerUser(user, roles);

        // Send verification email
        String verificationToken = generateVerificationToken();
        emailService.sendVerificationEmail(user.getEmail(), verificationToken);

        return ResponseEntity.ok(new MessageResponse("Đăng ký thành công! Vui lòng kiểm tra email để xác thực tài khoản."));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        boolean verified = userService.verifyEmail(token);
        if (verified) {
            return ResponseEntity.ok(new MessageResponse("Xác thực email thành công!"));
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Token không hợp lệ hoặc đã hết hạn"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        if (!userService.existsByEmail(email)) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Email không tồn tại"));
        }

        String resetToken = generateResetToken();
        userService.createPasswordResetToken(email, resetToken);
        emailService.sendPasswordResetEmail(email, resetToken);

        return ResponseEntity.ok(new MessageResponse("Vui lòng kiểm tra email để đặt lại mật khẩu"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(
            @RequestParam String token,
            @RequestParam String newPassword
    ) {
        boolean reset = userService.resetPassword(token, newPassword);
        if (reset) {
            return ResponseEntity.ok(new MessageResponse("Đặt lại mật khẩu thành công"));
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Token không hợp lệ hoặc đã hết hạn"));
    }

    private boolean isValidEmail(String email) {
        String regex = "^[A-Za-z0-9+_.-]+@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(email).matches();
    }

    private String generateVerificationToken() {
        // Generate random token
        return UUID.randomUUID().toString();
    }

    private String generateResetToken() {
        // Generate random token
        return UUID.randomUUID().toString();
    }
}