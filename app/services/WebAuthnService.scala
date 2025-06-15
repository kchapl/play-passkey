package services

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data._
import com.webauthn4j.data.client._
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.data.attestation.authenticator._
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.authenticator.{Authenticator, AuthenticatorImpl}
import com.webauthn4j.util.Base64Util
import com.fasterxml.jackson.databind.ObjectMapper
import play.api.libs.json.Json
import scala.jdk.CollectionConverters._
import java.util.{Collections => JCollections}
import scala.util.{Try, Success, Failure}
import java.security.SecureRandom
import com.webauthn4j.data.extension.client.{
  AuthenticationExtensionsClientInputs,
  RegistrationExtensionClientInput
}

trait WebAuthnService {

  /** Creates registration options for a new passkey
    * @param userId
    *   The user's ID
    * @return
    *   JSON containing the registration options
    */
  def createRegistrationOptions(userId: String): Try[String]

  /** Verifies and stores a new passkey registration
    * @param userId
    *   The user's ID
    * @param attestationObject
    *   Base64 encoded attestation object
    * @param clientDataJSON
    *   Base64 encoded client data JSON
    * @return
    *   Success if registration was successful, Failure with error message otherwise
    */
  def verifyRegistration(
      userId: String,
      attestationObject: String,
      clientDataJSON: String
  ): Try[Unit]

  /** Creates authentication options for an existing passkey
    * @param userId
    *   The user's ID
    * @return
    *   JSON containing the authentication options
    */
  def createAuthenticationOptions(userId: String): Try[String]

  /** Verifies a passkey authentication attempt
    * @param userId
    *   The user's ID
    * @param authenticatorData
    *   Base64 encoded authenticator data
    * @param clientDataJSON
    *   Base64 encoded client data JSON
    * @param signature
    *   Base64 encoded signature
    * @return
    *   Success if authentication was successful, Failure with error message otherwise
    */
  def verifyAuthentication(
      userId: String,
      authenticatorData: String,
      clientDataJSON: String,
      signature: String
  ): Try[Unit]
}

class WebAuthnServiceImpl(
    webAuthnConfig: WebAuthnConfig,
    random: java.security.SecureRandom
) extends WebAuthnService {
  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

  override def createRegistrationOptions(userId: String): Try[String] = {
    val userHandle = new Array[Byte](32)
    random.nextBytes(userHandle)

    val challenge = new DefaultChallenge()

    val rpEntity = new PublicKeyCredentialRpEntity(webAuthnConfig.rpId)

    val userEntity = new PublicKeyCredentialUserEntity(
      userHandle,
      userId,
      userId
    )

    val pubKeyCredParams = List(
      new PublicKeyCredentialParameters(
        PublicKeyCredentialType.PUBLIC_KEY,
        COSEAlgorithmIdentifier.ES256
      )
    )

    val authenticatorSelection = new AuthenticatorSelectionCriteria(
      AuthenticatorAttachment.PLATFORM,
      ResidentKeyRequirement.DISCOURAGED,
      UserVerificationRequirement.PREFERRED
    )

    val creationOptions = new PublicKeyCredentialCreationOptions(
      rpEntity,
      userEntity,
      challenge,
      pubKeyCredParams.asJava,
      None.orNull, // timeout
      JCollections.emptyList(), // excludeCredentials
      authenticatorSelection,
      AttestationConveyancePreference.NONE,
      new AuthenticationExtensionsClientInputs[RegistrationExtensionClientInput]() // extensions
    )

    // Convert to JSON using Jackson
    val mapper = new ObjectMapper()
    val json = mapper.writeValueAsString(creationOptions)

    Success(Json.stringify(Json.obj("publicKey" -> Json.parse(json))))
  }

  override def verifyRegistration(
      userId: String,
      attestationObject: String,
      clientDataJSON: String
  ): Try[Unit] = {
    val result = Try {
      val decodedClientDataJSON = Base64Util.decode(clientDataJSON)
      val decodedAttestationObject = Base64Util.decode(attestationObject)

      val challenge = new DefaultChallenge()
      val serverProperty = createServerProperty(
        challenge,
        webAuthnConfig.rpOrigin,
        webAuthnConfig.rpId
      )

      val registrationRequest =
        new RegistrationRequest(decodedAttestationObject, decodedClientDataJSON)
      val registrationData = webAuthnManager.parse(registrationRequest)
      val pubKeyCredParams = List(
        new PublicKeyCredentialParameters(
          PublicKeyCredentialType.PUBLIC_KEY,
          COSEAlgorithmIdentifier.ES256
        )
      )

      val registrationParameters = new RegistrationParameters(
        serverProperty,
        pubKeyCredParams.asJava,
        false,
        false
      )

      webAuthnManager.validate(registrationData, registrationParameters)

      val attestedCredentialData =
        registrationData.getAttestationObject.getAuthenticatorData.getAttestedCredentialData
      val credential = models.WebAuthnCredential(
        userId = userId,
        credentialId = attestedCredentialData.getCredentialId,
        coseKey = attestedCredentialData.getCOSEKey,
        signatureCount =
          registrationData.getAttestationObject.getAuthenticatorData.getSignCount.toLong
      )

      models.WebAuthnCredential.store(credential)
    }

    result
  }

  override def createAuthenticationOptions(userId: String): Try[String] = {
    val result = Try {
      val credential = models.WebAuthnCredential
        .findByUserId(userId)
        .getOrElse(throw new IllegalStateException("User not registered"))

      val challenge = new DefaultChallenge()

      val publicKeyJson = Json.obj(
        "challenge" -> Base64Util.encodeToString(challenge.getValue),
        "rpId" -> webAuthnConfig.rpId,
        "allowCredentials" -> Json.arr(
          Json.obj(
            "type" -> "public-key",
            "id" -> Base64Util.encodeToString(credential.credentialId)
          )
        ),
        "userVerification" -> "preferred"
      )

      Json.stringify(Json.obj("publicKey" -> publicKeyJson))
    }

    result
  }

  override def verifyAuthentication(
      userId: String,
      authenticatorData: String,
      clientDataJSON: String,
      signature: String
  ): Try[Unit] = {
    val result = Try {
      val credential = models.WebAuthnCredential
        .findByUserId(userId)
        .getOrElse(throw new IllegalStateException("User not registered"))

      val decodedClientDataJSON = Base64Util.decode(clientDataJSON)
      val decodedAuthenticatorData = Base64Util.decode(authenticatorData)
      val decodedSignature = Base64Util.decode(signature)

      val challenge = new DefaultChallenge()
      val serverProperty = createServerProperty(
        challenge,
        webAuthnConfig.rpOrigin,
        webAuthnConfig.rpId
      )

      val authenticationRequest = new AuthenticationRequest(
        credential.credentialId,
        decodedAuthenticatorData,
        decodedClientDataJSON,
        decodedSignature
      )
      val authenticationData = webAuthnManager.parse(authenticationRequest)

      val allowCredentials = List(
        new PublicKeyCredentialDescriptor(
          PublicKeyCredentialType.PUBLIC_KEY,
          credential.credentialId,
          JCollections.emptySet()
        )
      )

      val authenticator = createAuthenticator(
        credential.credentialId,
        credential.coseKey,
        credential.signatureCount
      )

      @annotation.nowarn("cat=deprecation")
      val authenticationParameters = new AuthenticationParameters(
        serverProperty,
        authenticator,
        allowCredentials.map(_.getId).asJava,
        true // User verification required
      )

      webAuthnManager.validate(authenticationData, authenticationParameters)

      models.WebAuthnCredential.store(
        credential.copy(
          signatureCount = authenticationData.getAuthenticatorData.getSignCount.toLong
        )
      )
    }

    result
  }

  // Private helper methods
  private def createServerProperty(
      challenge: DefaultChallenge,
      origin: String,
      rpId: String
  ): ServerProperty = {
    val origins = JCollections.singleton(new Origin(origin))
    new ServerProperty(origins, rpId, challenge)
  }

  private def createAuthenticator(
      credentialId: Array[Byte],
      coseKey: COSEKey,
      signatureCount: Long
  ): Authenticator = {
    new AuthenticatorImpl(
      new AttestedCredentialData(
        new AAGUID(Array.fill[Byte](16)(0)), // Default AAGUID
        credentialId,
        coseKey
      ),
      new NoneAttestationStatement(),
      signatureCount
    )
  }
}
