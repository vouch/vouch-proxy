# Changelog for Vouch Proxy

## Unreleased

Coming soon! Please document any work in progress here as part of your PR. It will be moved to the next tag when released.

* Implement a Discord provider that uses `Username` as the username to match against in the `whiteList` config
  * Or uses `Username#Discriminator` if the Discriminator is present
  * Or uses ID if `discord_use_ids` is set

## v0.40.0

- upgrade golang to `v1.22` from `v1.18`

## v0.39.0

- [add support for listening on unix domain sockets](https://github.com/vouch/vouch-proxy/pull/488)

## v0.38.0

- upgrade golang to `v1.18` from `v1.16`

## v0.37.0

- [allow configurable Write, Read and Idle timeouts for the http server](https://github.com/vouch/vouch-proxy/pull/468)

## v0.36.0

- [run Docker containers as non-root user](https://github.com/vouch/vouch-proxy/pull/444)

Permissions may need to be adjusted for `/config/secret` and `/config/config.yml` in Docker environemnts. See the [README](https://github.com/vouch/vouch-proxy#running-from-docker)

## v0.35.1

- [include DocumentRoot if configured in error pages](https://github.com/vouch/vouch-proxy/pull/439)

## v0.35.0

- [make session.MaxAge configurable](https://github.com/vouch/vouch-proxy/issues/318) to allow more time to login at the IdP

## v0.34.2

- [log github token only at `logLevel: debug`](https://github.com/vouch/vouch-proxy/pull/436)
- documentation edits
- move `cookie.sameSite` configuration to `cookie.Configure()`

## v0.34.1

- bug fix: [Azure provider no longer requires `oauth.user_info_url` to be configured](https://github.com/vouch/vouch-proxy/issues/417)

## v0.34.0

- add support for [the "claims" Request Parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) to support Twitch OIDC as IdP
- add [Twitch OIDC example](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example_twitch)

## v0.33.0

- [Vouch Proxy running in a path](https://github.com/vouch/vouch-proxy/issues/373)

## v0.32.0

- [Slack oidc example](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example_slack) and [slack app manifest](https://github.com/vouch/vouch-proxy/blob/master/examples/slack/vouch-slack-oidc-app-manifest.yml)
- [CHANGELOG.md](https://github.com/vouch/vouch-proxy/blob/master/CHANGELOG.md)

## v0.31.0

- [use quay.io](https://quay.io/repository/vouch/vouch-proxy?tab=tags) instead of Docker Hub for docker image hosting
- use [httprouter's](https://github.com/julienschmidt/httprouter) more performant mux

## v0.29.0

- embed static assets as templates using [go:embed](https://golang.org/pkg/embed/)

## v0.28.0

- add support for a custom 'relying party identifier' for ADFS

_the rest is history_ and can be teased out with `git log`
