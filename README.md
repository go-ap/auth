# About GoActivityPub: Authorization

[![MIT Licensed](https://img.shields.io/github/license/go-ap/auth.svg)](https://raw.githubusercontent.com/go-ap/auth/master/LICENSE)
[![Build Status](https://builds.sr.ht/~mariusor/auth.svg)](https://builds.sr.ht/~mariusor/auth)
[![Test Coverage](https://img.shields.io/codecov/c/github/go-ap/auth.svg)](https://codecov.io/gh/go-ap/auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-ap/auth)](https://goreportcard.com/report/github.com/go-ap/auth)

This project is part of the [GoActivityPub](https://github.com/go-ap) library which helps with creating ActivityPub applications using the Go programming language.

It is a wrapper package around making compatible libraries as [HTTP-Sig](https://github.com/go-fed/httpsig) and [OAuth2](https://github.com/openshift/osin) interact with GoActiivtyPub.

It provides functions to append Authorization headers to requests made with the client module, and also middlewares for verifying incoming requests against remote actors.

You can find an expanded documentation about the whole library [on SourceHut](https://man.sr.ht/~mariusor/go-activitypub/go-ap/index.md).

For discussions about the projects you can write to the discussions mailing list: [~mariusor/go-activitypub-discuss@lists.sr.ht](mailto:~mariusor/go-activitypub-discuss@lists.sr.ht)

For patches and bug reports please use the dev mailing list: [~mariusor/go-activitypub-dev@lists.sr.ht](mailto:~mariusor/go-activitypub-dev@lists.sr.ht)
