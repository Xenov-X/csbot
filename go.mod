module github.com/xenov-x/csbot

go 1.23

require gopkg.in/yaml.v3 v3.0.1

require github.com/xenov-x/csrest v0.0.0-20251128215248-e72f830b03fc

// Local development: comment out before pushing to csbot repo.
// Release workflow: push csrest first, then run `make sync` or
//   go get github.com/xenov-x/csrest@latest && go mod tidy
replace github.com/xenov-x/csrest => ../csrest
