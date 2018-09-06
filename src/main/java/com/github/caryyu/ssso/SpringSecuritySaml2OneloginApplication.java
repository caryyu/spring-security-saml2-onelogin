package com.github.caryyu.ssso;

import ch.qos.logback.access.tomcat.LogbackValve;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecuritySaml2OneloginApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecuritySaml2OneloginApplication.class, args);
	}

	@Bean
	public EmbeddedServletContainerFactory servletContainer() {
		TomcatEmbeddedServletContainerFactory tomcat = new TomcatEmbeddedServletContainerFactory();
		LogbackValve logbackValve = new LogbackValve();
		// point to logback-access.xml
		String filename = System.getProperty("logging.access", "logback-access.xml");
		logbackValve.setFilename(filename);
		tomcat.addContextValves(logbackValve);
		return tomcat;
	}
}
