package se.digg.wallet.r2ps.application.port.out;

import java.util.UUID;
import se.digg.wallet.r2ps.domain.model.StateInitRequest;

public interface StateInitRequestSpiPort {
  void send(StateInitRequest request, UUID deviceId);
}
