package se.digg.wallet.r2ps.commons.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

public class ServiceRequest extends ServiceExchange {

  @JsonProperty("client_id")
  private String clientID;

  @JsonProperty("kid")
  private String kid;

  @JsonProperty("context")
  private String context;

  /** The type of service exchange which determines the content of serviceData */
  @JsonProperty("type")
  private String serviceType;

  @JsonProperty("pake_session_id")
  private String pakeSessionId;

  public String getClientID() {
    return clientID;
  }

  public void setClientID(final String clientID) {
    this.clientID = clientID;
  }

  public String getKid() {
    return kid;
  }

  public void setKid(final String kid) {
    this.kid = kid;
  }

  public String getContext() {
    return context;
  }

  public void setContext(final String context) {
    this.context = context;
  }

  public String getServiceType() {
    return serviceType;
  }

  public void setServiceType(final String serviceType) {
    this.serviceType = serviceType;
  }

  public String getPakeSessionId() {
    return pakeSessionId;
  }

  public void setPakeSessionId(final String pakeSessionId) {
    this.pakeSessionId = pakeSessionId;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder extends AbstractBuilder<ServiceRequest, Builder> {

    public Builder() {
      super(new ServiceRequest());
    }

    @Override
    protected Builder getBuilder() {
      return this;
    }

    @Override
    protected void validate() {
      Objects.requireNonNull(this.serviceExchange.getClientID(), "The client ID is not set");
      Objects.requireNonNull(this.serviceExchange.getKid(), "The key identifier is not set");
      Objects.requireNonNull(
          this.serviceExchange.getServiceType(), "The exchange service type is not set");
    }

    public Builder clientID(final String clientID) {
      this.serviceExchange.setClientID(clientID);
      return this;
    }

    public Builder pakeSessionId(final String pakeSessionId) {
      this.serviceExchange.setPakeSessionId(pakeSessionId);
      return this;
    }

    public Builder kid(final String kid) {
      this.serviceExchange.setKid(kid);
      return this;
    }

    public Builder context(final String context) {
      this.serviceExchange.setContext(context);
      return this;
    }

    public Builder serviceType(final String serviceType) {
      this.serviceExchange.setServiceType(serviceType);
      return this;
    }
  }
}
