package com.example.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
        //동시 세션 제어
        http.sessionManagement()//세션 관리 기능이 작동함.
                .maximumSessions(1)//최대 허용 가능 세션수. -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false) //동시 로그인 차단함. -> 현재 사용가 차단. 기본값은 false -> 기존 세션 만료
                .expiredUrl("/expired")//세션이 만료될 경우 이동할 페이지
        ;


    }
}
