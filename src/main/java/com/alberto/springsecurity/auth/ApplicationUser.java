package com.alberto.springsecurity.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

public class ApplicationUser implements UserDetails {

    private final Set<? extends GrantedAuthority> grantedAuthorities;
    private final String password;
    private final String username;
    private final boolean isAccountNotExpired;
    private final boolean isAccountNotLocked;
    private final boolean isCredentialsNotExpired;
    private final boolean isEnabled;

    public ApplicationUser(Set<? extends GrantedAuthority> grantedAuthorities,
                           String password,
                           String username,
                           boolean isAccountNotExpired,
                           boolean isAccountNotLocked,
                           boolean isCredentialsNotExpired,
                           boolean isEnabled) {
        this.grantedAuthorities = grantedAuthorities;
        this.password = password;
        this.username = username;
        this.isAccountNotExpired = isAccountNotExpired;
        this.isAccountNotLocked = isAccountNotLocked;
        this.isCredentialsNotExpired = isCredentialsNotExpired;
        this.isEnabled = isEnabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.isAccountNotExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.isAccountNotLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.isCredentialsNotExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }
}
