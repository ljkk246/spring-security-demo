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
/**
 * Authentication 구조.
 * 당신이 누구 인지 증명하는것.
 * principal : 사용자 아이디, User 객체를 저장
 * credentials : 사용자 비밀번호
 * authorities : 인증된 사용자 권한 목록
 * details : 인증 부가 정보
 * Authenticated : 인증 여부
 */

/**
 * 사용자가 로그인 -> username, password ->
 * UsernamePasswordAuthenticationFilter 에서 principal : 아이디, credentials : 패스워드, Authenticated : false로 Authenitcation 객체를 만들고
 * AuthenticationManager에서  principal : UserDetails, credentials : ---,authorities : ROlE_ADMIN Authenticated : true로 Authenitcation 객체를
 * SecurityContextHolder의 SecurityContext에 저장한다.
 * (SC는 ThreadLocal로 되어 있어서 전역적으로 사용할 수 있다.
 *  인증이 필요한 자원 접근을 할 때 AbsctractSecurityInterceptor에서 SC를 먼저 조회해서 Authentication을 가져오기 때문에 또 인증처리를 거칠필요 가 없다.)
 * 즉 Authentication은 인증되기 전 UsernamePasswordAuthenticationFilter에서 생성되고,
 * AuthenticationManager로 인증 후에도 생성된다. 따라서 UsernamePasswordAuthenticationToken은 생성자가 2개.
 *
 * Authentication은 인터페이스. 이것을 구현한 게 UsernamePasswordAuthenticationToken, RememberMeAuthenticationToken 등이 있다.
 */

/**
 * SecurityContext
 * SecurityContext 안에 Authentication 객체가 저장.
 * 인증이 안료되면 'SPRING_SECURITY_CONTEXT' 라는 이름으로
 * HTTPSession에 저장되어 어플리케이션 전반에 걸쳐 전역적인 참조가 가능함.
 */

/**
 * SecurityContextHolder
 * 3가지 모드로 SecurityContext 객체를 저장한다.
 * MODE_THREADLOCAL: 기본값. 스레드당 SC 객체를 할당
 * MODE_IngeritableThreadLocal : 메인스레드와 자식 스레드까지 동일한 SC 유지
 * MODE_Global : 응용 프로그램에서 단 하나의 SC를 저장.
 * SecurityContextHolder.clearContext() : SC 기존 정보 초기화.
 * Authentication auth = SecurityContextHolder.getContext().getAuthentication();
 */
