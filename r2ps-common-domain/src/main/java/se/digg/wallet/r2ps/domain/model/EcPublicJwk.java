package se.digg.wallet.r2ps.domain.model;

public record EcPublicJwk(String kty, String crv, String x, String y, String kid) {}
