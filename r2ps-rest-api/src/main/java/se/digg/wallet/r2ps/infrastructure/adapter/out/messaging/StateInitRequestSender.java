package se.digg.wallet.r2ps.infrastructure.adapter.out.messaging;

import java.util.UUID;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import se.digg.wallet.r2ps.application.port.out.StateInitRequestSpiPort;
import se.digg.wallet.r2ps.domain.model.StateInitRequest;

@Service
public class StateInitRequestSender implements StateInitRequestSpiPort {

  private static final String DEST_TOPIC = "state-init-requests";

  private final KafkaTemplate<String, StateInitRequest> kafkaTemplate;

  public StateInitRequestSender(KafkaTemplate<String, StateInitRequest> kafkaTemplate) {
    this.kafkaTemplate = kafkaTemplate;
  }

  @Override
  public void send(StateInitRequest request, UUID deviceId) {
    kafkaTemplate.send(DEST_TOPIC, deviceId.toString(), request);
  }
}
