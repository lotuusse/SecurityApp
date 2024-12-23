package com.project.securitypf.dto;

import com.project.securitypf.entities.Role;
import lombok.Data;

@Data
public class SignUpRequest {
    private String username;
    private String email;
    private String password;
    private Role role;
}
