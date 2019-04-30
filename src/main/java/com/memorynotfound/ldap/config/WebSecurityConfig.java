package com.memorynotfound.ldap.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
		/*
		 * http .authorizeRequests() .antMatchers("/managers").hasRole("MANAGERS")
		 * .antMatchers("/employees").hasRole("XYZ") .anyRequest().fullyAuthenticated()
		 * .and() .formLogin();
		 */
        
        http.httpBasic().and().authorizeRequests().antMatchers("/managers**")
		.hasRole("MANAGERS").antMatchers("/employees**").hasRole("DEVELOPERS").and().formLogin().and()
		.csrf().disable().headers().frameOptions().disable();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .ldapAuthentication()
                    .userDnPatterns("uid={0},ou=OpsGroup")
                    .groupSearchBase("ou=OpsGroup")
                .contextSource(contextSource())
                .passwordCompare()
                    .passwordEncoder(new LdapShaPasswordEncoder())
                    .passwordAttribute("userPassword");
    }

    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
        return  new DefaultSpringSecurityContextSource(
                Collections.singletonList("ldap://newvoe1-dc01/dc=newvoe,dc=local"), "dc=newvoe,dc=local");
    }

    
	/*
	 * @Override public void configure(AuthenticationManagerBuilder auth) throws
	 * Exception { auth .ldapAuthentication() .userDnPatterns("uid={0},ou=people")
	 * .groupSearchBase("ou=groups") .contextSource(contextSource())
	 * .passwordCompare() .passwordEncoder(new LdapShaPasswordEncoder())
	 * .passwordAttribute("userPassword"); }
	 * 
	 *  @Bean
    public DefaultSpringSecurityContextSource contextSource() {
        return  new DefaultSpringSecurityContextSource(
                Collections.singletonList("ldap://localhost:12345"), "dc=memorynotfound,dc=com");
    }

	 * 
	 */
}