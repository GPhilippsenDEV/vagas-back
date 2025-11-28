package app.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {

	///////////////////////////////////////////////////////

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http    
		.csrf(AbstractHttpConfigurer::disable)
		.cors(AbstractHttpConfigurer::disable)
		.authorizeHttpRequests((requests) -> requests
				.requestMatchers("/api/login").permitAll()
				.requestMatchers("/api/candidato/save").permitAll()
				.requestMatchers("/api/empregador/save").permitAll()
				.requestMatchers("/api/vagas/findAll").permitAll()
				.requestMatchers("/api/vagas/findByTitulo").permitAll()
				.requestMatchers("/api/vagas/findByRequisito").permitAll()
				.requestMatchers("/api/vagas/findBySalario").permitAll()
				.requestMatchers("/api/vagas/findBySetor").permitAll()
				.requestMatchers("/api/vagas/findByDataAnuncio").permitAll()
				.requestMatchers("/api/vagas/findByTipo").permitAll()
				.requestMatchers("/api/vagas/findByNivelExperiencia").permitAll()

				.anyRequest().authenticated())
		.authenticationProvider(authenticationProvider)
		.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
		.sessionManagement(customizer -> customizer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}

	///////////////////////////////////////////////////////

	////commit teste

	@Autowired
	private JwtAuthenticationFilter jwtAuthFilter;

	@Autowired
	private AuthenticationProvider authenticationProvider;


	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.setAllowedOriginPatterns(Arrays.asList("*"));
		config.setAllowedHeaders(Arrays.asList(HttpHeaders.AUTHORIZATION,HttpHeaders.CONTENT_TYPE,HttpHeaders.ACCEPT));
		config.setAllowedMethods(Arrays.asList(HttpMethod.GET.name(),HttpMethod.POST.name(),HttpMethod.PUT.name(),HttpMethod.DELETE.name()));
		config.setMaxAge(3600L);
		source.registerCorsConfiguration("/**", config);
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(new CorsFilter(source));
		bean.setOrder(-102);
		return bean;
	}
	
	


}
