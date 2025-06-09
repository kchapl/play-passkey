package models

import play.api.libs.json.{Json, Format}
import com.webauthn4j.data.attestation.authenticator.COSEKey

case class WebAuthnCredential(
    userId: String,
    credentialId: Array[Byte],
    coseKey: COSEKey,
    signatureCount: Long,
    lastUsed: Long = System.currentTimeMillis()
) {
  def base64CredentialId: String =
    java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId)
}

object WebAuthnCredential {
  // In-memory storage for demo purposes. In a real application, use a database.
  private var credentials = Map[String, WebAuthnCredential]()

  def store(credential: WebAuthnCredential): Unit = {
    credentials += (credential.userId -> credential)
  }

  def findByUserId(userId: String): Option[WebAuthnCredential] = {
    credentials.get(userId)
  }
}
