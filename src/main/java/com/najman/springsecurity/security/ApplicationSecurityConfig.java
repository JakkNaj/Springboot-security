package com.najman.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.najman.springsecurity.security.ApplicationUserRole.*;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests((authz) -> authz
                        .requestMatchers(HttpMethod.GET,"/", "index.html", "/css/*", "/js/*")
                            .permitAll()
                        .requestMatchers("/api/**")
                            .hasRole(STUDENT.name())
                        .anyRequest().authenticated()
        )
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("linda"))
                .roles(STUDENT.name()) //ROLE_STUDENT
                .build();

        UserDetails jakubUser = User.builder()
                .username("kuba")
                .password(passwordEncoder.encode("admin"))
                .roles(ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
                .build();

        //MULTIPLE ROLES
        UserDetails marekUser = User.builder()
                .username("marek")
                .password(passwordEncoder.encode("marek"))
                .roles(ApplicationUserRole.TEACHER.name(), ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(jakubUser, lindaUser);
    }


}
