module github.com/go-ap/auth

go 1.25.0

require (
	git.sr.ht/~mariusor/lw v0.0.0-20250325163623-1639f3fb0e0d
	github.com/dadrus/httpsig v0.0.0-20260320084101-37048551fc59
	github.com/go-ap/activitypub v0.0.0-20260416122353-fb80985e153a
	github.com/go-ap/client v0.0.0-20260502172638-59507ebcf168
	github.com/go-ap/errors v0.0.0-20260208110149-e1b309365966
	github.com/go-ap/filters v0.0.0-20260416122840-724cb3c8974c
	github.com/go-ap/jsonld v0.0.0-20251216162253-e38fa664ea77
	github.com/go-fed/httpsig v1.1.0
	github.com/google/go-cmp v0.7.0
	github.com/openshift/osin v1.0.2-0.20220317075346-0f4d38c6e53f
)

require (
	git.sr.ht/~mariusor/cache v0.0.0-20250616110250-18a60a6f9473 // indirect
	git.sr.ht/~mariusor/go-xsd-duration v0.0.0-20220703122237-02e73435a078 // indirect
	git.sr.ht/~mariusor/mask v0.0.0-20250114195353-98705a6977b7 // indirect
	github.com/RoaringBitmap/roaring v1.9.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/go-chi/chi/v5 v5.2.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jdkato/prose v1.2.1 // indirect
	github.com/leporo/sqlf v1.4.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/mattn/goveralls v0.0.12 // indirect
	github.com/mfridman/tparse v0.18.0 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/term v0.42.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	gopkg.in/neurosnap/sentences.v1 v1.0.7 // indirect
	quamina.net/go/quamina/v2 v2.0.2 // indirect
)

replace github.com/common-fate/httpsig v0.2.1 => github.com/mariusor/httpsig-rfc9421 v0.0.0-20260427153044-0a866089c7cf

tool (
	github.com/mattn/goveralls
	github.com/mfridman/tparse
)
