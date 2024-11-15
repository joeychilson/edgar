# edgar

A Go library for accessing the SEC's EDGAR database.

## Installation

```bash
go get github.com/joeychilson/edgar
```

## Example

```go
package main

import (
	"context"
	"log"

	"github.com/joeychilson/edgar"
)

func main() {
	ctx := context.Background()

    // You should set a custom user agent or you will be rate limited.
	client := edgar.NewClient(edgar.WithUserAgent("CompanyName <contact@email.com>"))

	filings, err := client.Filings(ctx, "0000320193", &edgar.FilingFilter{
		Forms: []string{"10-K"},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, filing := range filings {
		log.Printf("%+v\n", filing)
	}
}
```
