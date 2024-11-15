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

	// You should set a custom user agent or you could be blocked if the default user agent is blocked.
	// You are allowed 10 requests per second
	client := edgar.NewClient(edgar.WithUserAgent("CompanyName <contact@email.com>"))

	tickers, err := client.CompanyList(ctx, &edgar.CompanyListFilter{
		Tickers: []string{"AAPL"},
	})
	if err != nil {
		log.Fatal(err)
	}

	filings, err := client.CompanyFilings(ctx, tickers[0].CIK, &edgar.FilingFilter{
		Forms: []string{"10-K"},
	})
	if err != nil {
		log.Fatal(err)
	}

	file, err := client.FilingDocuments(ctx, tickers[0].CIK, filings[0].AccessionNumber, &edgar.DocumentFilterOptions{
		Name: filings[0].PrimaryDocument,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v", file[0].Url)
}
```
