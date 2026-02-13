package se.digg.wallet.r2ps.application.port.out;

import se.digg.wallet.r2ps.domain.model.HsmWorkerRequest;

import java.util.UUID;

public interface RequestMessageSpiPort {
  void send(HsmWorkerRequest hsmWorkerRequest, UUID deviceId);
}
