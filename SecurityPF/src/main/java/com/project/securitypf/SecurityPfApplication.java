package com.project.securitypf;

import com.project.securitypf.entities.Role;
import com.project.securitypf.entities.User;
import com.project.securitypf.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SecurityPfApplication implements CommandLineRunner {
    @Autowired
    private UserRepository userRepository;

    public static void main(String[] args) {
        SpringApplication.run(SecurityPfApplication.class, args);
    }

    public void run(String... args) throws Exception {
        User adminAccount = userRepository.findByRole(Role.ADMIN);
        if(null == adminAccount) {
            User user = new User();

            user.setEmail("adminLoulou@gmail.com");
            user.setUsername("Admin");
            user.setRole(Role.ADMIN);
            user.setPassword(new BCryptPasswordEncoder().encode("@dmin&23"));
            userRepository.save(user);
        }

    }
}
