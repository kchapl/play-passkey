package modules

import play.api.ApplicationLoader
import play.api.ApplicationLoader.Context
import modules.AppComponents

class AppLoader extends ApplicationLoader {
  def load(context: Context) = {
    new AppComponents(context).application
  }
}
