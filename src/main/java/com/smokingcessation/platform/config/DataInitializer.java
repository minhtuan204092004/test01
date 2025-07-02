package com.smokingcessation.platform.config;

import com.smokingcessation.platform.entity.Role;
import com.smokingcessation.platform.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) {
        // Khởi tạo các Role mặc định nếu chưa tồn tại
        for (Role.RoleName roleName : Role.RoleName.values()) {
            if (!roleRepository.existsByName(roleName)) {
                Role role = new Role();
                role.setName(roleName);
                role.setDescription("Default " + roleName.toString() + " role");
                roleRepository.save(role);
            }
        }
    }
}
