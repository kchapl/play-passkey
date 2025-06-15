package modules

import play.api.ApplicationLoader
import play.api.ApplicationLoader.Context
import play.api.BuiltInComponentsFromContext
import play.api.routing.Router
import play.api.mvc.EssentialFilter
import play.filters.HttpFiltersComponents
import controllers.{HomeController, PasskeyController, AssetsComponents}
import play.api.http.HttpErrorHandler
import play.api.http.DefaultHttpErrorHandler
import play.api.Environment
import play.api.Mode
import play.api.Configuration
import services.{WebAuthnService, WebAuthnServiceImpl, WebAuthnConfig, WebAuthnConfigImpl}
import java.security.SecureRandom

class AppComponents(context: Context)
    extends BuiltInComponentsFromContext(context)
    with AssetsComponents
    with HttpFiltersComponents {

  // Configuration
  private val config = context.initialConfiguration
  private val environment = context.environment

  // Services
  private val webAuthnService: WebAuthnService = new WebAuthnServiceImpl
  private val webAuthnConfig: WebAuthnConfig = new WebAuthnConfigImpl(config)
  private val secureRandom = new SecureRandom()

  // Error handler
  override lazy val httpErrorHandler: HttpErrorHandler = new DefaultHttpErrorHandler(
    environment,
    config,
    None, // sourceMapper
    Some(router)
  )

  // Controllers
  lazy val homeController = new HomeController(controllerComponents)
  lazy val passkeyController = new PasskeyController(
    controllerComponents,
    webAuthnService,
    webAuthnConfig,
    secureRandom
  )

  // Router
  lazy val router: Router = new _root_.router.Routes(
    httpErrorHandler,
    homeController,
    passkeyController,
    assets
  )

  // Filters
  override def httpFilters: Seq[EssentialFilter] = super.httpFilters
}
