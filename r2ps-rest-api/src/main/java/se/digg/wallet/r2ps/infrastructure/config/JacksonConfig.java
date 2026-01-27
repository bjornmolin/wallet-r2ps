package se.digg.wallet.r2ps.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.digg.wallet.r2ps.domain.command.Command;
import se.digg.wallet.r2ps.domain.event.Event;
import se.digg.wallet.r2ps.domain.mapper.PublicKeyDeserializer;
import se.digg.wallet.r2ps.domain.mapper.PublicKeySerializer;
import se.digg.wallet.r2ps.domain.mapper.json.CommandDeserializer;
import se.digg.wallet.r2ps.domain.mapper.json.EventDeserializer;

import java.security.PublicKey;

@Configuration
public class JacksonConfig {

  @Bean
  public ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JavaTimeModule());
    mapper.registerModule(customSerializerDeserializerModule());
    mapper.registerModule(new Jdk8Module());

    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    return mapper;
  }

  @Bean
  public SimpleModule customSerializerDeserializerModule() {
    SimpleModule module = new SimpleModule();
    module.addDeserializer(Event.class, new EventDeserializer())
        .addDeserializer(Command.class, new CommandDeserializer())
        .addSerializer(PublicKey.class, new PublicKeySerializer())
        .addDeserializer(PublicKey.class, new PublicKeyDeserializer());

    return module;
  }

}
