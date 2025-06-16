lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .settings(
    organization := "k",
    name := "play-passkey",
    version := "0.1.0-SNAPSHOT",
    scalaVersion := "3.3.6",
    libraryDependencies ++= Seq(
      "com.webauthn4j" % "webauthn4j-core" % "0.29.3.RELEASE",
      "com.webauthn4j" % "webauthn4j-util" % "0.29.3.RELEASE",
      "org.slf4j" % "slf4j-api" % "2.0.17" % Runtime,
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.1" % Test
    ),
    dependencyOverrides ++= Seq(
      "com.fasterxml.jackson.core" % "jackson-databind" % "2.19.0" % Runtime,
      "com.fasterxml.jackson.core" % "jackson-core" % "2.19.1" % Runtime,
      "com.fasterxml.jackson.core" % "jackson-annotations" % "2.19.1" % Runtime,
      "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.19.0" % Runtime,
      "commons-beanutils" % "commons-beanutils" % "1.11.0" % Runtime
    )
  )
