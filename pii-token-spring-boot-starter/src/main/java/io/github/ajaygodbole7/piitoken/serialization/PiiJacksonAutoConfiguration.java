package io.github.ajaygodbole7.piitoken.serialization;

import io.github.ajaygodbole7.piitoken.runtime.GeneratedPiiModel;
import io.github.ajaygodbole7.piitoken.runtime.PiiTokenAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import tools.jackson.databind.json.JsonMapper;

@AutoConfiguration(after = PiiTokenAutoConfiguration.class)
@ConditionalOnClass({JsonMapper.class, JsonMapperBuilderCustomizer.class})
@ConditionalOnProperty(
        prefix = "pii",
        name = "jackson-suppression-enabled",
        havingValue = "true")
public class PiiJacksonAutoConfiguration {

    @Bean
    JsonMapperBuilderCustomizer piiProtectedFieldsJacksonCustomizer(
            GeneratedPiiModel generatedModel) {
        return builder -> builder.addModule(
                new PiiProtectedFieldsJacksonModule(generatedModel));
    }
}
