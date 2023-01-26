package com.alberto.springsecurity.auth.repository;

import com.alberto.springsecurity.auth.ApplicationUser;
import com.alberto.springsecurity.security.UserRole;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class ApplicationUserRepository implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public ApplicationUserRepository(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = List.of(
                new ApplicationUser(
                        UserRole.STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "alberto",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        UserRole.ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "admin",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        UserRole.ADMINTRAIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "admintrain",
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUsers;
    }
}
