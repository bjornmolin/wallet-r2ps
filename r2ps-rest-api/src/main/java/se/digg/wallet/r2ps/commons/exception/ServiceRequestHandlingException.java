package se.digg.wallet.r2ps.commons.exception;

import java.io.Serial;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;

public class ServiceRequestHandlingException extends Exception {
  @Serial
  private static final long serialVersionUID = 738529243418495043L;

  private final ErrorCode errorCode;

  public ServiceRequestHandlingException(final String message, final ErrorCode errorCode) {
    super(message);
    this.errorCode = errorCode;
  }

  public ServiceRequestHandlingException(
      final String message, final Throwable cause, final ErrorCode errorCode) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }
}
