package se.digg.wallet.r2ps.domain.model;

import java.util.UUID;

public record HsmWrapperRequest(UUID requestId, String stateJws, String outerRequestJws) {}
