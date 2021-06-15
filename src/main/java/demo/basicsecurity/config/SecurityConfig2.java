package demo.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;


@Configuration
@EnableWebSecurity
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception { 
        //인가
        http
            .authorizeRequests()
            .anyRequest()
            .authenticated()
            ;
        
        //인증
        http.formLogin();
        
        //메인 스레드와 자식 스레드에 관하여 동일한 SecurityContext 를 유지
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}
