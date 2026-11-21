# SPDX-License-Identifier: AGPL-3.0-or-later
# REQ: OPS-004 (ADR-1075, T39.5) - one leg of the image workflow: ONE BuildKit solve that compiles
# one architecture once and exports everything the leg needs from that single compile:
#   image  the final image: an OCI layout (the size gate), a loaded image (the smoke test) and,
#          when PUSH=true, the platform image pushed to the registry by digest (no tag);
#   bin    the `bin` stage: wrendns and wrendns.debug, the release assets.
# Both targets share the `build` stage, which BuildKit solves once. Driven by
# deploy/image/leg-build.sh; every value comes in through the environment.

variable "PLATFORM" { default = "linux/amd64" }
variable "ARCH" { default = "amd64" }
variable "PROFILE" { default = "release" }
variable "OUT" { default = "out" }
variable "IMAGE" { default = "" }
variable "PUSH" { default = "false" }
# "gha" reads and writes the GitHub cache (a speed-up only); anything else uses no cache.
# Writing it never fails a build (ignore-error): the cache service being down is not a build error.
# leg-build.sh sets "gha" only where the Actions runtime variables exist (see there).
variable "CACHE" { default = "none" }
variable "VERSION" { default = "dev" }
variable "REVISION" { default = "unknown" }
variable "WRENDNS_BUILD_VERSION" { default = "" }
variable "WRENDNS_BUILD_COMMIT" { default = "" }
variable "WRENDNS_BUILD_DATE" { default = "" }
variable "WRENDNS_BUILD_CHANNEL" { default = "dev" }
variable "SOURCE_DATE_EPOCH" { default = "" }
# The dependency layer's stamp (T39.4): the commit time of the last change to the dependency
# inputs, from deploy/image/deps-epoch.sh. Empty: the layer takes SOURCE_DATE_EPOCH.
variable "DEPS_DATE_EPOCH" { default = "" }

group "default" {
  targets = ["image", "bin"]
}

target "base" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = [PLATFORM]
  args = {
    PROFILE               = PROFILE
    VERSION               = VERSION
    REVISION              = REVISION
    WRENDNS_BUILD_VERSION = WRENDNS_BUILD_VERSION
    WRENDNS_BUILD_COMMIT  = WRENDNS_BUILD_COMMIT
    WRENDNS_BUILD_DATE    = WRENDNS_BUILD_DATE
    WRENDNS_BUILD_CHANNEL = WRENDNS_BUILD_CHANNEL
    SOURCE_DATE_EPOCH     = SOURCE_DATE_EPOCH
    DEPS_DATE_EPOCH       = DEPS_DATE_EPOCH
  }
  cache-from = CACHE == "gha" ? ["type=gha,scope=image-${ARCH}"] : []
}

target "image" {
  inherits = ["base"]
  # Written once, by this target: it holds every stage the other target needs.
  cache-to = CACHE == "gha" ? ["type=gha,scope=image-${ARCH},mode=max,ignore-error=true"] : []
  output = concat(
    ["type=oci,dest=${OUT}/image.tar", "type=docker,name=wrendns:smoke-${ARCH}"],
    PUSH == "true" ? ["type=image,name=${IMAGE},push-by-digest=true,name-canonical=true,push=true"] : []
  )
}

target "bin" {
  inherits = ["base"]
  target   = "bin"
  output   = ["type=local,dest=${OUT}/bin"]
}
