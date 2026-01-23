package se.digg.wallet.r2ps.infrastructure.adapter.out;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import se.digg.wallet.r2ps.application.port.out.R2psDeviceStateSpiPort;
import se.digg.wallet.r2ps.application.port.out.R2psResponseSinkSpiPort;
import se.digg.wallet.r2ps.domain.model.R2psResponse;
import se.digg.wallet.r2ps.infrastructure.config.Config;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class R2psDeviceStateValKey implements R2psDeviceStateSpiPort {

  private final RedisTemplate<String, String> redisTemplate;

  public R2psDeviceStateValKey(Config config, ObjectMapper objectMapper,
      RedisTemplate<String, String> redisTemplate) {
    this.redisTemplate = redisTemplate;
  }

  @Override
  public void save(String deviceId, String state) {
    redisTemplate.opsForValue().set(deviceId, state);
  }

  @Override
  public String load(String deviceId) {
    return redisTemplate.opsForValue().get(deviceId);
  }

}
