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
        http.sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true);
        //세션 제어 필터 : SessionManagementFilter, ConcurrentSessionFilter
        //SessionManagementFilter 는 세션 관리에 대한 filter이고 ConcurrentSessionFilter는 동시 세션 제어에 대한 filter다.
        //SessionManagementFilter 의 ConcurrentSessionControlAuthenticationStrategy : 세션이 이미 존재하는지 체크 함.
        //SessionManagementFilter 의 ChangeSessionIdAuthenticationStrategy : 세션 고정 보호처리를 함. 세션Id를 새로 만듬.
        //SessionManagementFilter 의 RegisterSessionAuthenticationStrategy : 사용자의 세션을 등록하고 저장함.
        //ConcurrentSessionFilter : session.isExpired -> ConcurrentSessionControlAuthenticationStrategy 호출 하여 세션 만료 체크함.
    }
}
