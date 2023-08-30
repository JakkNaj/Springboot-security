package com.najman.springsecurity.security;

import com.najman.springsecurity.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import static com.najman.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableMethodSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
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
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        //GET request for logout only when csrf is disabled, otherwise use POST
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID", "remember-me")
                        .logoutSuccessUrl("/login")
                );
        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
