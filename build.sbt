lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .settings(
    organization := "k",
    name := "play-passkey",
    version := "0.1.0-SNAPSHOT",
    scalaVersion := "3.3.6",
    resolvers ++= Seq(
      "Maven Central" at "https://repo1.maven.org/maven2/",
      "JCenter" at "https://jcenter.bintray.com",
      "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots",
      "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases",
      Resolver.mavenLocal
    ),
    libraryDependencies ++= Seq(
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.1" % Test,
      "com.webauthn4j" % "webauthn4j-core" % "0.29.3.RELEASE",
      "com.webauthn4j" % "webauthn4j-util" % "0.29.3.RELEASE",
      "com.google.guava" % "guava" % "32.1.2-jre",
      "org.slf4j" % "slf4j-api" % "2.0.7",
      "com.fasterxml.jackson.core" % "jackson-databind" % "2.19.0",
      "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.19.0"
    )
  )
  .settings(
    dependencyOverrides := Seq(
      "com.fasterxml.jackson.core" % "jackson-databind" % "2.19.0",
      "com.fasterxml.jackson.core" % "jackson-core" % "2.19.0",
      "com.fasterxml.jackson.core" % "jackson-annotations" % "2.19.0",
      "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.19.0"
    )
  )
