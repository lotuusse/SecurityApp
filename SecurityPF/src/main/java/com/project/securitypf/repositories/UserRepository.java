package com.project.securitypf.repositories;

import com.project.securitypf.entities.Role;
import com.project.securitypf.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);

    User findByRole(Role role);
}
