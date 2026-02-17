package se.digg.wallet.r2ps.infrastructure.adapter.in.messaging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import se.digg.wallet.r2ps.application.port.out.R2psDeviceStateSpiPort;
import se.digg.wallet.r2ps.domain.model.StateInitResponse;

@Service
public class StateInitResponseReceiver {

  private static final Logger log = LoggerFactory.getLogger(StateInitResponseReceiver.class);

  private final ObjectMapper objectMapper;
  private final R2psDeviceStateSpiPort deviceStateSpiPort;
  private final StateInitResponseCache responseCache;

  public StateInitResponseReceiver(
      ObjectMapper objectMapper,
      R2psDeviceStateSpiPort deviceStateSpiPort,
      StateInitResponseCache responseCache) {
    this.objectMapper = objectMapper;
    this.deviceStateSpiPort = deviceStateSpiPort;
    this.responseCache = responseCache;
  }

  @KafkaListener(topics = "state-init-responses", groupId = "${r2ps.in.group-id}")
  public void consume(ConsumerRecord<String, String> record) {
    String key = record.key();
    StateInitResponse response = null;

    try {
      response = objectMapper.readValue(record.value(), StateInitResponse.class);
    } catch (JsonProcessingException e) {
      log.error("Could not deserialize state init response: {}", record.value(), e);
      return;
    }

    log.info(
        "Received state init response - Key: {}, clientId: {}, requestId: {}",
        key,
        response.clientId(),
        response.requestId());

    // Save state to Redis
    deviceStateSpiPort.save(response.clientId(), response.stateJws());
    log.debug("Saved state to Redis for clientId: {}", response.clientId());

    // Cache full response (for dev_authorization_code)
    responseCache.put(response.requestId(), response);
  }
}
