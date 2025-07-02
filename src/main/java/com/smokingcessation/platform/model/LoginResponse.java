package com.smokingcessation.platform.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private Long userId;
    private String username;
    private String email;
    private String fullName;
    private String accessToken;
    private String role;
    private String message;
}
