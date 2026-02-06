package se.digg.wallet.r2ps.application.port.out;

import se.digg.wallet.r2ps.domain.model.HsmWrapperRequest;

import java.util.UUID;

public interface RequestMessageSpiPort {
  void send(HsmWrapperRequest hsmWrapperRequest, UUID walletId);
}
