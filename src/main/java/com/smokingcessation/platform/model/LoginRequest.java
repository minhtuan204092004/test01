package com.smokingcessation.platform.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
//    private String username;
//    private String password;
@NotBlank(message = "Email không được để trống")
@Email(message = "Email không hợp lệ")
private String email;

    @NotBlank(message = "Mật khẩu không được để trống")
    private String password;
}
