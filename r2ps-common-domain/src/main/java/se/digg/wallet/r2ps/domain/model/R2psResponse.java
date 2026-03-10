package se.digg.wallet.r2ps.domain.model;

import java.util.Optional;
import java.util.UUID;

public record R2psResponse(UUID requestId, Optional<String> stateJws, Optional<String> outerResponseJws, String status, String errorMessage) {
}
