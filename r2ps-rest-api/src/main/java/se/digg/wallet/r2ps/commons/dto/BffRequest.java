package se.digg.wallet.r2ps.commons.dto;

public class BffRequest {
  private String clientId;
  private String outerRequestJws;

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getOuterRequestJws() {
    return outerRequestJws;
  }

  public void setOuterRequestJws(String outerRequestJws) {
    this.outerRequestJws = outerRequestJws;
  }
}
