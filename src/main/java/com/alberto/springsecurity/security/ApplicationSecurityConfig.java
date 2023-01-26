package com.alberto.springsecurity.security;

import com.alberto.springsecurity.auth.jwt.JwtConfig;
import com.alberto.springsecurity.auth.jwt.JwtTokenVerifierFilter;
import com.alberto.springsecurity.auth.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    private ApplicationContext applicationContext;

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     UserDetailsService userDetailsService,
                                     ApplicationContext applicationContext,
                                     SecretKey secretKey,
                                     JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.applicationContext = applicationContext;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // All of this executes one by one in the same order we specify here
        http
                // CSRF uses a perRequestFilter CSRF filter that examines all the request looking for de CSRF token
                // If there is no token or the token is invalid, then the request will not pass the filter
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.and()
                //
                .csrf().disable() // cross site request forgery (basically a illegal copy of something like document, signature, etc)
                // only enable for browser client users and not for API consumed by non browser client.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(applicationContext.getBean(AuthenticationManager.class), jwtConfig, secretKey))
                // Executes JwtTokenVerifierFilter after the second one
                .addFilterAfter(new JwtTokenVerifierFilter(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/login").permitAll()
                .antMatchers("/api/**").hasRole(UserRole.STUDENT.name())
                //.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(UserPermission.COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(UserPermission.COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(UserPermission.COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(UserRole.ADMIN.name(), UserRole.ADMINTRAIN.name())
                .anyRequest()
                .authenticated();
                //.and()
                //.authenticationProvider(daoAuthenticationProvider())
                //.httpBasic(); // Base64 enconding, user&pass wihtin the request headers. Can't logout
                //.formLogin()
                    //.loginPage("/login")
                //    .permitAll()
                //    .defaultSuccessUrl("/")
                //    .passwordParameter("password")
                //    .usernameParameter("username")
                //.and()
                // default 2 week (sessionId by default 30 min) need to pass remember me checkbox in client (saved on cookie user, exp time and md5 of all the info)
                //.rememberMe()
                //    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                //    .key("somethingsecuredhere")
                //    .rememberMeParameter("remember-me")
                //.and()
                //.logout()
                //    .logoutUrl("/logout")
                //    .clearAuthentication(true)
                //    .invalidateHttpSession(true)
                //    .deleteCookies("remember-me", "JSESSIONID")
                //    .logoutSuccessUrl("/login");

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            web.ignoring().antMatchers("/css/*", "/js/*"); // what is public
        };
    }

    // For login form authentication
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder); // allows passwords to be decoded
        provider.setUserDetailsService(userDetailsService);

        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
