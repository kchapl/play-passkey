package modules

import play.api.ApplicationLoader
import play.api.ApplicationLoader.Context
import play.api.BuiltInComponentsFromContext
import play.api.routing.Router
import controllers.{HomeController, PasskeyController, AssetsComponents}

class AppComponents(context: Context)
    extends BuiltInComponentsFromContext(context)
    with AssetsComponents {

  override def httpFilters = Seq.empty

  // Controllers
  lazy val homeController = new HomeController(controllerComponents)
  lazy val passkeyController = new PasskeyController(controllerComponents)

  // Router
  lazy val router: Router =
    new _root_.router.Routes(httpErrorHandler, homeController, passkeyController, assets)
}
