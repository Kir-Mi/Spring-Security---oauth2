package com.example.SpringSecurityoauth2.config;

import com.example.SpringSecurityoauth2.model.User;
import com.example.SpringSecurityoauth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserRepository userRepository;

    @Autowired
    public SecurityConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request ->
                        request
                                .requestMatchers("/user").hasAuthority("USER")
                                .requestMatchers("/admin").hasAuthority("ADMIN")
                                .anyRequest().permitAll())
                .formLogin(form -> form.loginPage("/login")
                        .defaultSuccessUrl("/user", true))
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(userAuthoritiesMapper())));
        return http.build();
    }


    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return authorities -> {
            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (authority instanceof OAuth2UserAuthority oAuth2UserAuthority) {
                    Map<String, Object> userAttributes = oAuth2UserAuthority.getAttributes();
                    String username = (String) userAttributes.get("name");
                    String email = (String) userAttributes.get("email");
                    Integer id = (Integer) userAttributes.get("id");
                    User user = userRepository.findById(id).orElseGet(() -> {
                        User createUser = User.builder()
                                .id(id)
                                .name(username)
                                .email(email)
                                .role("USER")
                                .build();
                        userRepository.save(createUser);
                        return createUser;
                    });
                    grantedAuthorities.add(new SimpleGrantedAuthority(user.getRole()));
                }
            });
            return grantedAuthorities;
        };
    }
}
