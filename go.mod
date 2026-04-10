module github.com/xenov-x/csbot

go 1.23

require gopkg.in/yaml.v3 v3.0.1

require github.com/xenov-x/csrest v0.0.0-20260410143551-a41e6d81a848

// Local development: comment out before pushing to csbot repo.
// Release workflow: push csrest first, then run `make sync` or
//   go get github.com/xenov-x/csrest@latest && go mod tidy
replace github.com/xenov-x/csrest => ../csrest
