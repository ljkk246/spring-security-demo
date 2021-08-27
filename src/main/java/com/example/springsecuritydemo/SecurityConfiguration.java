package com.example.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
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
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    //사용자 생성.
    //noop prefix는 패스워드 암호화 방식을 나타냄.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
        //지금은 ADMIN, SYS, USER 일일이 지정해야하지만 나중에 ADMIN 권한은 ADMIN만 넣으면 되게끔 하는 방법 배움.
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);//원래 가고자 했던 요청정보가 저장됨. 이 객체를 얻어와서 다음 필터에 넘겨주는 필터는 RequestCacheAwareFilter이다.
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                });//인증에 성공한 유저가 원래 가고자 했던 곳으로 이동하게 함.

        //FilterSecurityInterceptor가 요청을 받고 있음.
        //user자원에 인증되지 않은 사용자가 접근하면 이 필터는 인증 예외를 발생시킴.
        //더 정확하게는 인가예외로 감. 인증자체를 받으려는 시도를 안했기 때문. 즉 익명사용자가 접근하는 것이므로 인가예외로 빠짐.
        //인가예외로 보냈을 때 AccessDeniedException에서 AccessDeniedHandler로 가지 않고 AuthenticationException으로 이동시켜서 로그인리다이렉트, 로그인시도 했던 사용자 요청정보를 캐싱한다.

        //만약, 인증된 사용자지만 권한이 없는 사용자라면 인가 예외가 발생한다.
        //이때는 AccessDeniedException에서 AccessDeniedHandler를 호출해서 후속 작업을 처리한다.

        http.exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");//직접 만든 페이지로 이동하게 됨.
                    }
                })//인증 예외 시 처리
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });//인가 예외 시 처리

    }

}
