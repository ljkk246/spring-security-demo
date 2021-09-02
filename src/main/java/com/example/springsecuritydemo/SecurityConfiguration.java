package com.example.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@Order(0)//같은 설정클래스가 2개이므로 order로 순서를 구분지어야 한다. order 순서에 따라 시큐리티가 어느 설정 클래스를 먼저 검사하는 지 달라진다.
//어느 설정 클래스를 먼저 검사하는지에 따라서 url matches 검사가 달라지므로, 넓은 범위의 url 검사하는 게 더 나중에 이루어져야 한다.
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }
}
@Order(1)
@Configuration
class SecurityConfiguration2 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin();
        //WebSecurity.java엘서 FIlterChainProxy 객체를 생성할 때 생성자 매개변수로 springFilterChains를 넣어주는데
        //springFilterChains 에 config1,2에 대한 정보가 들어간다.
        //사용자 요청에 따라 config1로 갈건지, config2로 갈건지 결정이 되는데. 이 결정하는 부분은 FIlterChainProxy.class에서 한다.

    }
}