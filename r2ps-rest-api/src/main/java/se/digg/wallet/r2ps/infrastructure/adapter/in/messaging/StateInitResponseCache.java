package se.digg.wallet.r2ps.infrastructure.adapter.in.messaging;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import se.digg.wallet.r2ps.domain.model.StateInitResponse;

@Service
public class StateInitResponseCache {

  private static final Logger log = LoggerFactory.getLogger(StateInitResponseCache.class);

  private final Map<String, StateInitResponse> cache = new ConcurrentHashMap<>();

  public void put(String requestId, StateInitResponse response) {
    log.debug("Caching state init response for requestId: {}", requestId);
    cache.put(requestId, response);
  }

  public Optional<StateInitResponse> waitForResponse(String requestId, Duration timeout) {
    Instant deadline = Instant.now().plus(timeout);
    log.debug("Waiting for state init response requestId: {}, timeout: {}", requestId, timeout);

    while (Instant.now().isBefore(deadline)) {
      StateInitResponse response = cache.remove(requestId);
      if (response != null) {
        log.debug("Found state init response for requestId: {}", requestId);
        return Optional.of(response);
      }

      try {
        Thread.sleep(50);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        log.warn("Interrupted while waiting for state init response: {}", requestId);
        return Optional.empty();
      }
    }

    log.warn("Timeout waiting for state init response requestId: {}", requestId);
    return Optional.empty();
  }
}
