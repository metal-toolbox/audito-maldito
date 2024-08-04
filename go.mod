module github.com/metal-toolbox/audito-maldito

go 1.19

require (
	github.com/cenkalti/backoff/v4 v4.2.1
	github.com/elastic/go-libaudit/v2 v2.3.3
	github.com/fsnotify/fsnotify v1.7.0
	github.com/go-logr/zapr v1.2.4
	github.com/metal-toolbox/auditevent v0.8.0
	github.com/prometheus/client_golang v1.17.0
	github.com/stretchr/testify v1.8.4
	go.uber.org/zap v1.26.0
	golang.org/x/sync v0.8.0
)

replace github.com/elastic/go-libaudit/v2 v2.3.3 => github.com/metal-toolbox/go-libaudit/v2 v2.3.3

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.4.1-0.20230718164431-9a2bf3000d16 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.11.1 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
