lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .settings(
    organization := "k",
    name := "play-passkey",
    version := "0.1.0-SNAPSHOT",
    javacOptions ++= Seq("-release", "21"),
    scalaVersion := "3.3.6",
    libraryDependencies ++= Seq(
      guice,
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.1" % Test
    )
  )
