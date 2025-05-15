package controllers

import org.scalatestplus.play._
import play.api.Application
import play.api.ApplicationLoader
import play.api.test._
import play.api.test.Helpers._

/** Add your spec here. We're using compile-time DI as configured in AppComponents.
  */
class HomeControllerSpec extends PlaySpec with StubControllerComponentsFactory {

  "HomeController GET" should {

    "render Hello World from a new instance of controller" in {
      val controller = new HomeController(stubControllerComponents())
      val home = controller.index.apply(FakeRequest(GET, "/"))

      status(home) mustBe OK
      contentType(home) mustBe Some("text/html")
      contentAsString(home) must include("Welcome to Play")
    }

    "render Hello World from the router" in {
      val app = new TestApplicationFactory().createApplication
      val request = FakeRequest(GET, "/")
      val home = route(app, request).get

      status(home) mustBe OK
      contentType(home) mustBe Some("text/html")
      contentAsString(home) must include("Welcome to Play")
    }
  }
}

/** Test application factory that uses our AppComponents */
trait ApplicationFactory {
  def createApplication: Application
}

class TestApplicationFactory extends ApplicationFactory {
  override def createApplication: Application = {
    import play.api.Environment
    import play.api.Mode
    import modules.AppComponents

    val env = Environment.simple()
    val context = ApplicationLoader.Context.create(env)
    new AppComponents(context).application
  }
}
