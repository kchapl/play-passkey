package controllers

import models.WebAuthnCredential
import play.api.mvc._
import play.api.libs.json._
import utils.WebAuthn4jWrapper

import com.webauthn4j.data._
import com.webauthn4j.data.client._
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.data.extension.client._
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.data.attestation.authenticator._
import com.webauthn4j.data.attestation.statement._
import com.webauthn4j.util.Base64UrlUtil

import scala.jdk.CollectionConverters._
import javax.inject.Inject
import scala.util.{Try, Success, Failure}
import scala.concurrent.ExecutionContext
import java.security.SecureRandom

class PasskeyController @Inject() (val cc: ControllerComponents)(implicit ec: ExecutionContext)
    extends AbstractController(cc) {
  private val rpId = "localhost" // Replace with your domain in production
  private val rpOrigin = "http://localhost:9000" // Replace with your origin in production
  private val random = new SecureRandom()

  def startRegistration(userId: String): Action[AnyContent] = Action {
    implicit request: Request[AnyContent] =>
      val userHandle = new Array[Byte](32)
      random.nextBytes(userHandle)

      val challenge = new DefaultChallenge()

      val publicKeyJson = Json.obj(
        "challenge" -> Base64UrlUtil.encodeToString(challenge.getValue),
        "rp" -> Json.obj(
          "name" -> "Play Passkey Demo",
          "id" -> rpId
        ),
        "user" -> Json.obj(
          "id" -> Base64UrlUtil.encodeToString(userHandle),
          "name" -> userId,
          "displayName" -> userId
        ),
        "pubKeyCredParams" -> Json.arr(
          Json.obj(
            "type" -> WebAuthn4jWrapper.PUBLIC_KEY_TYPE,
            "alg" -> WebAuthn4jWrapper.ES256_ALGORITHM
          )
        ),
        "authenticatorSelection" -> Json.obj(
          "requireResidentKey" -> false,
          "userVerification" -> "preferred"
        )
      )

      Ok(Json.obj("publicKey" -> publicKeyJson))
  }

  def finishRegistration(userId: String): Action[JsValue] = Action(parse.json) { implicit request =>
    val result = Try {
      val clientDataJSON =
        Base64UrlUtil.decode((request.body \ "response" \ "clientDataJSON").as[String])
      val attestationObject =
        Base64UrlUtil.decode((request.body \ "response" \ "attestationObject").as[String])

      val challenge = new DefaultChallenge()

      val serverProperty = new ServerProperty(
        new Origin(rpOrigin),
        rpId,
        new DefaultChallenge()
      )

      val registrationData =
        WebAuthn4jWrapper.parseRegistrationRequest(attestationObject, clientDataJSON)
      val pubKeyCredParams = WebAuthn4jWrapper.createPublicKeyCredentialParameters()

      val registrationParameters = new RegistrationParameters(
        serverProperty,
        pubKeyCredParams.asJava,
        false,
        false
      )

      WebAuthn4jWrapper.validateRegistration(registrationData, registrationParameters)

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
          "challenge" -> Base64UrlUtil.encodeToString(challenge.getValue),
          "rpId" -> rpId,
          "allowCredentials" -> Json.arr(
            Json.obj(
              "type" -> WebAuthn4jWrapper.PUBLIC_KEY_TYPE,
              "id" -> Base64UrlUtil.encodeToString(credential.credentialId)
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
          Base64UrlUtil.decode((request.body \ "response" \ "clientDataJSON").as[String])
        val authenticatorData =
          Base64UrlUtil.decode((request.body \ "response" \ "authenticatorData").as[String])
        val signature = Base64UrlUtil.decode((request.body \ "response" \ "signature").as[String])

        val serverProperty = new ServerProperty(
          new Origin(rpOrigin),
          rpId,
          null
        )

        val authenticationData = WebAuthn4jWrapper.parseAuthenticationRequest(
          credential.credentialId,
          authenticatorData,
          clientDataJSON,
          signature
        )

        val allowCredentials = List(
          new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.credentialId,
            null
          )
        )

        val attestedCredentialData = new AttestedCredentialData(
          new AAGUID(Array.fill[Byte](16)(0)),
          credential.credentialId,
          credential.coseKey
        )

        val authenticator = new com.webauthn4j.authenticator.Authenticator {
          override def getAttestedCredentialData: AttestedCredentialData = attestedCredentialData
          override def getCounter: Long = credential.signatureCount
          override def setCounter(count: Long): Unit = {
            WebAuthnCredential.store(credential.copy(signatureCount = count))
          }
        }

        val authenticationParameters = new AuthenticationParameters(
          serverProperty,
          authenticator,
          allowCredentials.map(_.getId).asJava,
          true,
          true
        )

        WebAuthn4jWrapper.validateAuthentication(authenticationData, authenticationParameters)

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
