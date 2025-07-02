package com.smokingcessation.platform.service;

import com.smokingcessation.platform.entity.User;
import com.smokingcessation.platform.model.LoginRequest;
import com.smokingcessation.platform.model.LoginResponse;
import com.smokingcessation.platform.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Username or password is incorrect"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Username or password is incorrect");
        }

        if (user.getStatus() != User.UserStatus.ACTIVE) {
            throw new RuntimeException("Account is not active");
        }

        // TODO: In thực tế sẽ generate JWT token ở đây
        String mockToken = "mock-jwt-token-" + System.currentTimeMillis();

        return new LoginResponse(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getFullName(),
            mockToken,
            user.getRoles().stream().findFirst().map(role -> role.getName().toString()).orElse("MEMBER"),
            "Login successful!"
        );
    }
}
