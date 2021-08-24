package com.example.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin();

        http.rememberMe()
                .userDetailsService(userDetailsService);

        //세션 정책
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        //Always : 항상 세션을 생성함.
        //If_Requried : 필요할떄만 생성(기본값)
        //Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용하긴 함.
        //Stateless : 스프링 시큐리티가 생성하지도 않고 존재해도 사용하지 않음 -> 세션을 사용하지 않은 인증방식을 사용하려고 할떄 사용. 예를들면 jwt 토큰
        ;


    }
}
