package controllers

import play.api.mvc.*

class HomeController(cc: ControllerComponents) extends AbstractController(cc) {
  def index = Action {
    Ok(views.html.index())
  }
}
