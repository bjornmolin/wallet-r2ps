package se.digg.wallet.r2ps.domain.model;

public record StateInitRequest(String requestId, String clientId, EcPublicJwk publicKey) {}
