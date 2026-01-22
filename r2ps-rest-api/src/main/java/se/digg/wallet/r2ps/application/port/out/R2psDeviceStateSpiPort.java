package se.digg.wallet.r2ps.application.port.out;

public interface R2psDeviceStateSpiPort {
  void save(String deviceId, String state);

  String load(String deviceId);

}
