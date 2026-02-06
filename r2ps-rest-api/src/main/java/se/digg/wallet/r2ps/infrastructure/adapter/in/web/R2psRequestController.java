package se.digg.wallet.r2ps.infrastructure.adapter.in.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import se.digg.wallet.r2ps.application.dto.AsyncResponseDto;
import se.digg.wallet.r2ps.application.dto.AsyncResponseError;
import se.digg.wallet.r2ps.application.dto.AsyncResponseStatus;
import se.digg.wallet.r2ps.application.port.in.R2psResponseUseCase;
import se.digg.wallet.r2ps.application.port.out.R2psDeviceStateSpiPort;
import se.digg.wallet.r2ps.application.port.out.R2psResponseSinkSpiPort;
import se.digg.wallet.r2ps.application.port.out.RequestMessageSpiPort;
import se.digg.wallet.r2ps.application.service.R2psResponseService;
import se.digg.wallet.r2ps.commons.dto.BffRequest;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.domain.model.HsmWrapperRequest;
import se.digg.wallet.r2ps.domain.model.R2psResponse;
import se.digg.wallet.r2ps.infrastructure.config.Config;
import se.digg.wallet.r2ps.infrastructure.service.UrlFormatterService;

@RestController
public class R2psRequestController {

  private static final Logger log = LoggerFactory.getLogger(R2psRequestController.class);
  private final ObjectMapper objectMapper;
  private final R2psDeviceStateSpiPort r2psDeviceStateSpiPort;
  private final RequestMessageSpiPort requestMessageSpiPort;
  private final R2psResponseUseCase r2psResponseUseCase;
  private final UrlFormatterService urlFormatter;

  private final boolean syncResponseSupport;
  private final long maxResponseTimeoutInMillis;

  public R2psRequestController(
      ObjectMapper objectMapper,
      final R2psDeviceStateSpiPort r2psDeviceStateSpiPort,
      final RequestMessageSpiPort requestMessageSpiPort,
      R2psResponseSinkSpiPort r2psResponseSinkSpiPort,
      UrlFormatterService urlFormatter,
      Config config) {
    this.objectMapper = objectMapper;
    this.r2psDeviceStateSpiPort = r2psDeviceStateSpiPort;
    this.requestMessageSpiPort = requestMessageSpiPort;
    this.urlFormatter = urlFormatter;
    syncResponseSupport = config.getKafka().rest().serveSync();
    maxResponseTimeoutInMillis = config.getKafka().rest().syncTimeoutMs();
    r2psResponseUseCase = new R2psResponseService(r2psResponseSinkSpiPort, r2psDeviceStateSpiPort);
  }

  public static ECKey pemToECKey(String pem) throws Exception {
    // Remove PEM headers and whitespace
    String pemContent =
        pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

    // Decode base64
    byte[] encodedKey = Base64.getDecoder().decode(pemContent);

    // Create X509 key spec
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);

    // Generate EC public key
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(keySpec);

    // Convert to Nimbus ECKey using the Builder
    return new ECKey.Builder(Curve.P_256, publicKey).build();
  }

  @GetMapping("/task/{correlationId}")
  public ResponseEntity<AsyncResponseDto<String>> taskResponse(@PathVariable UUID correlationId) {

    Optional<R2psResponse> r2psResponse =
        r2psResponseUseCase.waitForR2psResponse(correlationId, maxResponseTimeoutInMillis);
    if (r2psResponse.isEmpty()) {
      URI location = urlFormatter.responseEventsUrl(correlationId);
      AsyncResponseDto<String> responseBody =
          new AsyncResponseDto<>(
              correlationId,
              AsyncResponseStatus.PENDING,
              Optional.empty(),
              Optional.of(location),
              Optional.empty());
      log.info("registerResponseDto pending {}", responseBody);
      return ResponseEntity.accepted().location(location).body(responseBody);
    }

    if (r2psResponse.get().httpStatus() != HttpStatus.OK.value()) {
      Optional<AsyncResponseError> errorPayload = parseErrorPayload(r2psResponse.get());

      AsyncResponseDto<String> registerResponseDto =
          new AsyncResponseDto<>(
              correlationId,
              AsyncResponseStatus.COMPLETE,
              Optional.empty(),
              Optional.empty(),
              errorPayload);
      return ResponseEntity.status(r2psResponse.get().httpStatus()).body(registerResponseDto);
    }

    AsyncResponseDto<String> registerResponseDto =
        new AsyncResponseDto<>(
            correlationId,
            AsyncResponseStatus.COMPLETE,
            Optional.of(r2psResponse.get().serviceResponseJws()),
            Optional.empty(),
            Optional.empty());
    log.info("registerResponseDto {}", registerResponseDto);

    return ResponseEntity.ok(registerResponseDto);
  }

  @PostMapping(
      value = "/",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<AsyncResponseDto<String>> service(@RequestBody final BffRequest bffRequest)
      throws Exception {
    if (log.isDebugEnabled()) {
      logServiceRequest(bffRequest.getOuterRequestJws());
    }

    UUID deviceId = UUID.fromString(bffRequest.getClientId());
    UUID walletId = UUID.fromString(bffRequest.getClientId()); // TODO

    String stateJws = r2psDeviceStateSpiPort.load(deviceId.toString());

    if (stateJws == null) {
      stateJws = initializeState(deviceId, walletId);
    }

    UUID requestId = UUID.randomUUID();
    HsmWrapperRequest hsmWrapperRequest =
        new HsmWrapperRequest(requestId, stateJws, bffRequest.getOuterRequestJws());
    log.info("Sending service request:\n{}", objectMapper.writeValueAsString(hsmWrapperRequest));
    requestMessageSpiPort.send(hsmWrapperRequest, walletId);

    if (syncResponseSupport) {
      log.info("Waiting for synchronous response for requestId: {}", requestId);
      return taskResponse(requestId);
    }

    URI location = urlFormatter.responseEventsUrl(requestId);
    AsyncResponseDto<String> responseBody =
        new AsyncResponseDto<>(
            requestId,
            AsyncResponseStatus.PENDING,
            Optional.empty(),
            Optional.of(location),
            Optional.empty());
    return ResponseEntity.accepted().location(location).body(responseBody);
  }

  @PostMapping(
      value = "/service",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> legacySyncService(@RequestBody final BffRequest serviceRequestJws)
      throws Exception {
    ResponseEntity<AsyncResponseDto<String>> serviceResponse = this.service(serviceRequestJws);
    if (serviceResponse.getBody() != null && serviceResponse.getBody().result().isPresent()) {
      String body = serviceResponse.getBody().result().get();
      log.info("Response {} {}", serviceResponse.getStatusCode(), body);
      return ResponseEntity.status(serviceResponse.getStatusCode()).body(body);
    }
    return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).build();
  }

  private void logServiceRequest(final String serviceRequest) {
    log.trace("Service request JWS: {}", serviceRequest);
    try {
      JWSObject jwsObject = JWSObject.parse(serviceRequest);
      if (log.isTraceEnabled()) {
        log.trace(
            "Sending service request:\n{}",
            objectMapper.writeValueAsString(jwsObject.getPayload().toJSONObject()));
      }
    } catch (JsonProcessingException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private Optional<AsyncResponseError> parseErrorPayload(R2psResponse r2psResponse) {
    // TODO this is not working since we're not sending error payloads on Kafka
    try {
      ServiceRequestHandlingException serviceRequestHandlingException =
          objectMapper.readValue(
              r2psResponse.serviceResponseJws(), ServiceRequestHandlingException.class);
      if (serviceRequestHandlingException != null) {
        log.info("Parsed error payload: {}", serviceRequestHandlingException.getMessage());
        return Optional.of(
            new AsyncResponseError(
                serviceRequestHandlingException.getMessage(),
                serviceRequestHandlingException.getErrorCode().getResponseCode()));
      }
    } catch (JsonProcessingException e) {
      log.debug("Could not parse error payload", e);
    }
    return Optional.empty();
  }

  private String initializeState(UUID deviceId, UUID walletId) throws Exception {
    // TODO should register initial state with a specific service
    String clientPublicKeyPem =
        """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE233YaUniXpEuNY15ZyJmqi+t4VtH
        E0BsFyM6fMWvL4xtdiD7u8u2eTZlWsK/XrYPCobERUbPaKUJ9W+l19CWUA==
        -----END PUBLIC KEY-----
        """;

    ECKey clientPublicKey = pemToECKey(clientPublicKeyPem);

    ECKey ecKey =
        new com.nimbusds.jose.jwk.gen.ECKeyGenerator(Curve.P_256)
            .keyID("example-key-id")
            .generate();

    ECPrivateKey privateKey = ecKey.toECPrivateKey();

    return generateInitialDeviceHsmStateJws(
        deviceId.toString(), walletId.toString(), clientPublicKey.toPublicJWK(), privateKey);
  }

  private String generateInitialDeviceHsmStateJws(
      String clientId, String walletId, JWK clientPublicKeyJwk, ECPrivateKey privateKey)
      throws JOSEException {

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

    // Build the claims set matching DeviceHsmState structure
    JWTClaimsSet claimsSet =
        new JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim("wallet_id", walletId)
            .claim("client_public_key", clientPublicKeyJwk.toJSONObject())
            .claim("keys", new ArrayList<>())
            .build();

    // Create signed JWT
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);

    // Sign with EC private key
    JWSSigner signer = new ECDSASigner(privateKey);
    signedJWT.sign(signer);

    // Return serialized JWS
    return signedJWT.serialize();
  }
}
