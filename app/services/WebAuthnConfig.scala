package services

import play.api.Configuration

trait WebAuthnConfig {
  def rpId: String
  def rpOrigin: String
}

class WebAuthnConfigImpl(config: Configuration) extends WebAuthnConfig {
  override val rpId: String = config.get[String]("webauthn.rpId")
  override val rpOrigin: String = config.get[String]("webauthn.rpOrigin")
}
