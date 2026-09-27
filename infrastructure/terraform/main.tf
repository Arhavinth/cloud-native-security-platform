terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_network" "security_platform" {
  name = "security-platform-network"
}

resource "docker_container" "local_registry" {
  name  = "security-platform-registry"
  image = "registry:2"

  ports {
    internal = 5000
    external = 5000
  }

  networks_advanced {
    name = docker_network.security_platform.name
  }

  restart = "unless-stopped"
}