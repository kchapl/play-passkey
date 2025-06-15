package controllers

import models.WebAuthnCredential
import play.api.mvc._
import play.api.libs.json._
import services.{WebAuthnService, WebAuthnConfig}
import scala.concurrent.ExecutionContext
import scala.util.{Try, Success, Failure}

class PasskeyController(
    cc: ControllerComponents,
    webAuthnService: WebAuthnService
)(using ec: ExecutionContext)
    extends AbstractController(cc) {

  def startRegistration(userId: String): Action[Unit] = Action(parse.empty) { _ =>
    webAuthnService.createRegistrationOptions(userId) match {
      case Success(json) => Ok(Json.parse(json))
      case Failure(e)    => BadRequest(Json.obj("error" -> e.getMessage))
    }
  }

  def finishRegistration(userId: String): Action[JsValue] = Action(parse.json) { request =>
    val attestationObject = (request.body \ "response" \ "attestationObject").as[String]
    val clientDataJSON = (request.body \ "response" \ "clientDataJSON").as[String]

    webAuthnService.verifyRegistration(userId, attestationObject, clientDataJSON) match {
      case Success(_) => Ok(Json.obj("status" -> "registered"))
      case Failure(e) => BadRequest(Json.obj("error" -> e.getMessage))
    }
  }

  def startAuthentication(userId: String): Action[Unit] = Action(parse.empty) { _ =>
    webAuthnService.createAuthenticationOptions(userId) match {
      case Success(json) => Ok(Json.parse(json))
      case Failure(e)    => BadRequest(Json.obj("error" -> e.getMessage))
    }
  }

  def finishAuthentication(userId: String): Action[JsValue] = Action(parse.json) {
    (request: Request[JsValue]) =>
      val authenticatorData = (request.body \ "response" \ "authenticatorData").as[String]
      val clientDataJSON = (request.body \ "response" \ "clientDataJSON").as[String]
      val signature = (request.body \ "response" \ "signature").as[String]

      webAuthnService.verifyAuthentication(
        userId,
        authenticatorData,
        clientDataJSON,
        signature
      ) match {
        case Success(_) => Ok(Json.obj("status" -> "authenticated"))
        case Failure(e) => BadRequest(Json.obj("error" -> e.getMessage))
      }
  }

  def protectedEndpoint: Action[AnyContent] = Action { (request: Request[AnyContent]) =>
    // In a real application, you would validate the session here
    Unauthorized("Please authenticate first")
  }
}
