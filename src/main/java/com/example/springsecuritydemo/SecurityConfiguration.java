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

        //세션 고정 보호
        //인증에 성공 할때 마다 새로운 세션 id를 발급해주는 것.
        http.sessionManagement()
                .sessionFixation().changeSessionId()//changeSessionId()는 기본값. none, migrateSession, newSession 의 설정이 가능.
        //migrateSessionrr과 changeSessionId : 이전 세션에 설정된 토큰값을 그대로 사용하지만, newSession은 아예 새로운 세션을 만든다.
        //none : 세션을 새로 생성하지 않음.
        ;


    }
}
