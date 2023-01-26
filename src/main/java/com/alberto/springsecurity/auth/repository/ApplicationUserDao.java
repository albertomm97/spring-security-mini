package com.alberto.springsecurity.auth.repository;

import com.alberto.springsecurity.auth.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {

    public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
