package com.najman.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.concurrent.TimeUnit;

import static com.najman.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableMethodSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                //cookie will be inaccessible to the client side script
                //.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .csrf(csrf -> csrf.disable()) //using postman during the course
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers(HttpMethod.GET,"/", "index.html", "/css/*", "/js/*")
                            .permitAll()
                        .requestMatchers("/api/**")
                            .hasRole(ADMIN.name())
                        //replaced with @PreAuthorize(...) in StudentManagementController
                        /*.requestMatchers(HttpMethod.DELETE,"management/api/**")
                            .hasAuthority(STUDENT_DELETE.getPermission())
                        .requestMatchers(HttpMethod.POST,"management/api/**")
                            .hasAuthority(STUDENT_WRITE.getPermission())
                        .requestMatchers(HttpMethod.GET,"/management/api/**")
                            .hasAnyRole(ADMIN.name(), TEACHER.name())*/
                        .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .permitAll()
                        .defaultSuccessUrl("/courses", true)
                )
                ;
        return http.build();
    }

    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("linda"))
                //.roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails jakubUser = User.builder()
                .username("kuba")
                .password(passwordEncoder.encode("admin"))
                //.roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        //MULTIPLE ROLES
        UserDetails marekUser = User.builder()
                .username("marek")
                .password(passwordEncoder.encode("marek"))
                //.roles(TEACHER.name(), STUDENT.name()) //ROLE_ADMIN
                .authorities(TEACHER.getGrantedAuthorities())
                //.authorities(ADMIN.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                jakubUser,
                lindaUser,
                marekUser
        );
    }


}
