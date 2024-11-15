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

	tickers, err := client.SearchCompanies(ctx, &edgar.CompanyFilterOptions{
		Tickers: []string{"AAPL"},
	})
	if err != nil {
		log.Fatal(err)
	}

	filings, err := client.Filings(ctx, tickers[0].CIK, &edgar.FilingFilterOptions{
		Forms: []string{"10-K"},
	})
	if err != nil {
		log.Fatal(err)
	}

	files, err := client.FilingDirectory(ctx, tickers[0].CIK, filings[0].AccessionNumber, &edgar.FilingDirectoryFilterOptions{
		DocumentName: filings[0].PrimaryDocument,
	})
	if err != nil {
		log.Fatal(err)
	}

	contents, err := client.FileContents(ctx, files[0].URL)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(contents))
}
```
