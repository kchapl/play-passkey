package utils

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data._
import com.webauthn4j.data.attestation.authenticator._
import com.webauthn4j.data.attestation.statement._
import com.webauthn4j.data.client._
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.util.Base64UrlUtil

import scala.jdk.CollectionConverters._
import java.util.{Collections => JCollections}

object WebAuthn4jWrapper {
  // Create a non-strict manager to be more tolerant of different implementations
  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

  // Constants
  val ES256_ALGORITHM = -7
  val PUBLIC_KEY_TYPE = "public-key"

  def createPublicKeyCredentialParameters(): List[PublicKeyCredentialParameters] = {
    List(
      new PublicKeyCredentialParameters(
        PublicKeyCredentialType.PUBLIC_KEY,
        COSEAlgorithmIdentifier.ES256
      )
    )
  }

  def parseRegistrationRequest(
      attestationObject: Array[Byte],
      clientDataJSON: Array[Byte]
  ): RegistrationData = {
    val request = new RegistrationRequest(attestationObject, clientDataJSON)
    webAuthnManager.parse(request)
  }

  def validateRegistration(
      registrationData: RegistrationData,
      parameters: RegistrationParameters
  ): RegistrationData = {
    // Note: Using validate method is still the recommended approach in 0.29.3
    // We accept the deprecation warning as the newer methods are not available yet
    @annotation.nowarn("cat=deprecation")
    def validate = webAuthnManager.validate(registrationData, parameters)
    validate
  }

  def parseAuthenticationRequest(
      credentialId: Array[Byte],
      authenticatorData: Array[Byte],
      clientDataJSON: Array[Byte],
      signature: Array[Byte]
  ): AuthenticationData = {
    val request = new AuthenticationRequest(
      credentialId,
      authenticatorData,
      clientDataJSON,
      signature
    )
    webAuthnManager.parse(request)
  }

  def validateAuthentication(
      authenticationData: AuthenticationData,
      parameters: AuthenticationParameters
  ): AuthenticationData = {
    // Note: Using validate method is still the recommended approach in 0.29.3
    // We accept the deprecation warning as the newer methods are not available yet
    @annotation.nowarn("cat=deprecation")
    def validate = webAuthnManager.validate(authenticationData, parameters)
    validate
  }
}
