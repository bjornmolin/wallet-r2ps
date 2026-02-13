package se.digg.wallet.r2ps.infrastructure.adapter.out.messaging;

import java.util.UUID;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import se.digg.wallet.r2ps.application.port.out.RequestMessageSpiPort;
import se.digg.wallet.r2ps.domain.model.HsmWorkerRequest;

@Service
public class RequestMessageSender implements RequestMessageSpiPort {

  private static final String DEST_TOPIC = "r2ps-requests";

  private final KafkaTemplate<String, HsmWorkerRequest> kafkaTemplate;

  public RequestMessageSender(KafkaTemplate<String, HsmWorkerRequest> kafkaTemplate) {
    this.kafkaTemplate = kafkaTemplate;
  }

  @Override
  public void send(HsmWorkerRequest hsmWorkerRequest, UUID deviceId) {
    kafkaTemplate.send(DEST_TOPIC, deviceId.toString(), hsmWorkerRequest);
  }
}
