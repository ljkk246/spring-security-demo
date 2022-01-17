package com.example.springsecuritydemo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    //authentication와 authentication1이 같은지 비교
    @GetMapping("/")
    public String index(HttpSession httpSession) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); //bp
        SecurityContext attribute = (SecurityContext) httpSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = attribute.getAuthentication();
        return "home";
    }

    //위의 authentication과 같은지 비교 (ThreadLocal으로 저장되기 때문에 다르다.)
    @GetMapping("/thread")
    public String thread() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); //bp
            }
        }).start();
        return "thread";
    }
}
