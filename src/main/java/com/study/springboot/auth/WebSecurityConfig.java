package com.study.springboot.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;


@Configuration      // 스프링 설정
@EnableWebSecurity  // 스프링 시큐리티 설정 기능 활성화
public class WebSecurityConfig {


    // 시큐리티 설정 내용 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // "/" 경로 요청에 대해 모두 허용
                .antMatchers("/").permitAll()
                // 해당 경로에대해서 모두 허용 ( 정적 파일 )
                .antMatchers("/css/**", "/js/**", "/img/**").permitAll()
                // 해당 경로에 대해 모두 허용
                .antMatchers("/guest/**").permitAll()
                // 해당 역할에 대해서만 모두 허용
                .antMatchers("/member/**").hasAnyRole("USER", "ADMIN")
                // 해당 역할에 대해서만 모두 허용
                .antMatchers("/admin/**").hasRole("ADMIN")

                // ROLE_ADMIN 에서 "ROLE_" 는 자동으로 붙는다

                // 적용
                .anyRequest().authenticated();

        // 로그인 요청은 모두에게 허용한다
        http.formLogin()
                .permitAll();

        // 로그아웃 요청은 모두에게 허용한다
        http.logout()
                .permitAll();

        return http.build();

    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() throws Exception {
        // 인메모리 방식의 인증을 사용하고
        // 인증 사용자를 등록한다 user, admin ( id, passwor,d roles )

        // 테스트용으로는 사용가능함
//        UserDetails user = User.withDefaultPasswordEncoder()
//                        .username("user").password(passwordEncoder().encode("1234"))
//                        .roles("USER")
//                        .username("admin").password(passwordEncoder().encode("1234"))
//                        .roles("ADMIN")
//                        .build();

         //단일 사용자 - 리스트
//        UserDetails user = User.withDefaultPasswordEncoder()
//                            .username("user").password("1234")
//                            .roles("USER").build();
//
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                            .username("admin").password("1234")
//                            .roles("ADMIN").build();
//
//        List<UserDetails> list = new ArrayList<>();
//        list.add(user);
//        list.add(admin);
//
//        return new InMemoryUserDetailsManager(list);


         //여러 사용자 - 빌더
        User.UserBuilder users = User.withDefaultPasswordEncoder();

        User user = (User) users.username("user").password("1234")
                .roles("USER").build();
        User admin = (User) users.username("admin").password("1234")
                .roles("ADMIN").build();

        return new InMemoryUserDetailsManager(user, admin);


    }


    // passwordEncoder() 추가
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


// 구버전 방식
//@Configuration      // 스프링 설정
//@EnableWebSecurity  // 스프링 시큐리티 설정 기능 활성화
//public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//
//    // 시큐리티 설정 내용 구성
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        /**
//         * 네트워크, 서버 ACL과 같은 패턴이다
//         * 점점 좁히는식, 뒤에꺼가 앞에꺼를 덮어씌운다
//         */
//        http.authorizeRequests()
//                // "/" 경로 요청에 대해 모두 허용
//                .antMatchers("/").permitAll()
//                // 해당 경로에대해서 모두 허용 ( 정적 파일 )
//                .antMatchers("/css/**", "/js/**", "/img/**").permitAll()
//                // 해당 경로에 대해 모두 허용
//                .antMatchers("/guest/**").permitAll()
//                // 해당 역할에 대해서만 모두 허용
//                .antMatchers("/member/**").hasAnyRole("USER", "ADMIN")
//                // 해당 역할에 대해서만 모두 허용
//                .antMatchers("/admin/**").hasRole("ADMIN")
//
//                // ROLE_ADMIN 에서 "ROLE_" 는 자동으로 붙는다
//
//                // 적용
//                .anyRequest().authenticated();
//
//        // 로그인 요청은 모두에게 허용한다
//        http.formLogin()
//                .permitAll();
//
//        // 로그아웃 요청은 모두에게 허용한다
//        http.logout()
//                .permitAll();
//    }
//
//    @Override
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        // 인메모리 방식의 인증을 사용하고
//        // 인증 사용자를 등록한다 user, admin ( id, passwor,d roles )
//        auth.inMemoryAuthentication()
//                // id: user , password: 1234, roles: USER 사용자를 등록
//                .withUser("user").password(passwordEncoder().encode("1234"))
//                .roles("USER")
//                .and()
//                // id: admin , password: 1234, roles: ADMIN 사용자를 등록
//                .withUser("admin").password(passwordEncoder().encode("1234"))
//                .roles("ADMIN");
//    }
//
//
//    // passwordEncoder() 추가
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//}
