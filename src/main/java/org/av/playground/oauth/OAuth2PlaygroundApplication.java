package org.av.playground.oauth;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
@EnableOAuth2Client
public class OAuth2PlaygroundApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	public static void main(String[] args) {
		SpringApplication.run(OAuth2PlaygroundApplication.class, args);
	}
	
	@Bean
	@ConfigurationProperties("security.oauth2.facebook")
	public ClientResources fbOAuth2() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("security.oauth2.github")
	public ClientResources githubOAuth2() {
		return new ClientResources();
	}
	
	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	// Configure the security filter chain that carries the OAuth2 authentication processor.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
		.antMatcher("/**")
		.authorizeRequests()
			// Switch off security for home page, login, and static resources
			.antMatchers("/", "/login**", "/webjars/**")
			.permitAll()
		.anyRequest()
			// Request authentication for all other requests.
			.authenticated()
		 .and()
		 	// Clear the session and invalidate the cookie. Built in support for a /logout endpoint by Spring Security.
		 	// The logout /logout endpoint requires a POST.
		 	// In order to prevent Cross Site Request Forgery (CSRF) a token linked to the current session is needed in the reqest XSRF-TOKEN.
		 	.logout()
		 	.logoutSuccessUrl("/")
		 	.permitAll()
		.and()
			.csrf()
			.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			// HttpOnly attribute on the cookie for protecting the cookie.
		.and()
			.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		// @formatter:on
	}

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(fbOAuth2(), "/login/facebook"));
		filters.add(ssoFilter(githubOAuth2(), "/login/github"));
		filter.setFilters(filters);
		return filter;
	}

	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(),
				client.getClient().getClientId());
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		return filter;
	}

	class ClientResources {

		@NestedConfigurationProperty
		private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

		@NestedConfigurationProperty
		private ResourceServerProperties resource = new ResourceServerProperties();

		public AuthorizationCodeResourceDetails getClient() {
			return client;
		}

		public ResourceServerProperties getResource() {
			return resource;
		}
	}
}
