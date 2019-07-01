package com.github.millgi.security.springsecuritytest

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest
import org.springframework.boot.actuate.health.HealthEndpoint
import org.springframework.boot.actuate.info.InfoEndpoint
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.servlet.PathRequest
import org.springframework.boot.autoconfigure.security.servlet.StaticResourceRequest
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@EnableWebSecurity
@SpringBootApplication
class SpringSecurityTestApplication

@Configuration
class SecurityConfiguration : WebSecurityConfigurerAdapter() {

    override fun configure(web: WebSecurity?) {
        web!!.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .antMatchers("/**/*.html")
    }

    override fun configure(http: HttpSecurity?) {
        http!!.authorizeRequests()
                .antMatchers("/hello/**").hasRole("USER")
                .antMatchers("/bonjour/**").hasRole("UTILISATEUR")
                .requestMatchers(EndpointRequest.to(HealthEndpoint::class.java, InfoEndpoint::class.java)).hasRole("ADMIN")
                .anyRequest().denyAll()
                .and()
                .httpBasic()
    }

    override fun configure(auth: AuthenticationManagerBuilder?) {
        auth!!.inMemoryAuthentication()
                .withUser("user").password("user").authorities("ROLE_USER").and()
                .withUser("utilisateur").password("utilisateur").authorities("ROLE_UTILISATEUR").and()
                .withUser("admin").password("admin").authorities("ROLE_ADMIN")
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PlainTextPasswordEncoder()
    }

}

class PlainTextPasswordEncoder: PasswordEncoder {
    override fun encode(rawPassword: CharSequence?): String {
        return rawPassword.toString()
    }

    override fun matches(rawPassword: CharSequence?, encodedPassword: String?): Boolean {
        return encode(rawPassword) == encodedPassword
    }
}

@RestController
class HelloController {

    @GetMapping(value = ["/hello"], produces = [MimeTypeUtils.TEXT_PLAIN_VALUE])
    fun hello(): String = "Hello world!"

    @GetMapping(value = ["/bonjour"], produces = [MimeTypeUtils.TEXT_PLAIN_VALUE])
    fun bonjour(): String = "Bonjour le monde!"

}

fun main(args: Array<String>) {
    runApplication<SpringSecurityTestApplication>(*args)
}
