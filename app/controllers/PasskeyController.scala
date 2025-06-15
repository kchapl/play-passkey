package controllers

import models.WebAuthnCredential
import play.api.mvc._
import play.api.libs.json._
import services.{WebAuthnService, WebAuthnConfig}
import com.webauthn4j.data._
import com.webauthn4j.data.client._
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.util.Base64Util
import com.fasterxml.jackson.databind.ObjectMapper

import scala.jdk.CollectionConverters._
import scala.util.{Try, Success, Failure}
import scala.concurrent.ExecutionContext
import java.security.SecureRandom
import java.util.{Collections => JCollections}

class PasskeyController(
    cc: ControllerComponents,
    webAuthnService: WebAuthnService,
    webAuthnConfig: WebAuthnConfig,
    random: SecureRandom
)(implicit ec: ExecutionContext)
    extends AbstractController(cc) {

  def startRegistration(userId: String): Action[AnyContent] = Action {
    implicit request: Request[AnyContent] =>
      val userHandle = new Array[Byte](32)
      random.nextBytes(userHandle)

      val challenge = new DefaultChallenge()

      val rpEntity = new PublicKeyCredentialRpEntity(webAuthnConfig.rpId)

      val userEntity = new PublicKeyCredentialUserEntity(
        userHandle,
        userId,
        userId
      )

      val pubKeyCredParams = webAuthnService.createPublicKeyCredentialParameters()

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
        null, // timeout
        null, // excludeCredentials
        authenticatorSelection,
        AttestationConveyancePreference.NONE,
        null // extensions
      )

      // Convert to JSON using Jackson
      val mapper = new ObjectMapper()
      val json = mapper.writeValueAsString(creationOptions)

      Ok(Json.obj("publicKey" -> Json.parse(json)))
  }

  def finishRegistration(userId: String): Action[JsValue] = Action(parse.json) { implicit request =>
    val result = Try {
      val clientDataJSON =
        Base64Util.decode((request.body \ "response" \ "clientDataJSON").as[String])
      val attestationObject =
        Base64Util.decode((request.body \ "response" \ "attestationObject").as[String])

      val challenge = new DefaultChallenge()
      val serverProperty = webAuthnService.createServerProperty(
        challenge,
        webAuthnConfig.rpOrigin,
        webAuthnConfig.rpId
      )

      val registrationData =
        webAuthnService.parseRegistrationRequest(attestationObject, clientDataJSON)
      val pubKeyCredParams = webAuthnService.createPublicKeyCredentialParameters()

      val registrationParameters = new RegistrationParameters(
        serverProperty,
        pubKeyCredParams.asJava,
        false,
        false
      )

      webAuthnService.validateRegistration(registrationData, registrationParameters)

      val attestedCredentialData =
        registrationData.getAttestationObject.getAuthenticatorData.getAttestedCredentialData
      val credential = WebAuthnCredential(
        userId = userId,
        credentialId = attestedCredentialData.getCredentialId,
        coseKey = attestedCredentialData.getCOSEKey,
        signatureCount =
          registrationData.getAttestationObject.getAuthenticatorData.getSignCount.toLong
      )

      WebAuthnCredential.store(credential)

      Json.obj("status" -> "registered")
    }

    result match {
      case Success(jsValue) => Ok(jsValue)
      case Failure(e)       => BadRequest(Json.obj("error" -> e.getMessage))
    }
  }

  def startAuthentication(userId: String): Action[AnyContent] = Action {
    implicit request: Request[AnyContent] =>
      val result = Try {
        val credential = WebAuthnCredential
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

        Json.obj("publicKey" -> publicKeyJson)
      }

      result match {
        case Success(jsValue) => Ok(jsValue)
        case Failure(e)       => BadRequest(Json.obj("error" -> e.getMessage))
      }
  }

  def finishAuthentication(userId: String): Action[JsValue] = Action(parse.json) {
    implicit request: Request[JsValue] =>
      val result = Try {
        val credential = WebAuthnCredential
          .findByUserId(userId)
          .getOrElse(throw new IllegalStateException("User not registered"))

        val clientDataJSON =
          Base64Util.decode((request.body \ "response" \ "clientDataJSON").as[String])
        val rawAuthenticatorData =
          Base64Util.decode((request.body \ "response" \ "authenticatorData").as[String])
        val signature = Base64Util.decode((request.body \ "response" \ "signature").as[String])

        val challenge = new DefaultChallenge()
        val serverProperty = webAuthnService.createServerProperty(
          challenge,
          webAuthnConfig.rpOrigin,
          webAuthnConfig.rpId
        )

        val authenticationData = webAuthnService.parseAuthenticationRequest(
          credential.credentialId,
          rawAuthenticatorData,
          clientDataJSON,
          signature
        )

        val allowCredentials = List(
          new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.credentialId,
            JCollections.emptySet()
          )
        )

        val authenticator = webAuthnService.createAuthenticator(
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

        webAuthnService.validateAuthentication(authenticationData, authenticationParameters)

        WebAuthnCredential.store(
          credential.copy(
            signatureCount = authenticationData.getAuthenticatorData.getSignCount.toLong
          )
        )

        Json.obj("status" -> "authenticated")
      }

      result match {
        case Success(jsValue) => Ok(jsValue)
        case Failure(e)       => BadRequest(Json.obj("error" -> e.getMessage))
      }
  }

  def protectedEndpoint: Action[AnyContent] = Action { implicit request: Request[AnyContent] =>
    // In a real application, you would validate the session here
    Unauthorized("Please authenticate first")
  }
}
