package edgar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Client is a http client for interacting with EDGAR
type Client struct {
	userAgent   string
	httpClient  *http.Client
	rateLimiter *rate.Limiter
}

// ClientOption allows for customization of the client
type ClientOption func(*Client)

// NewClient creates a new EDGAR client
func NewClient(options ...ClientOption) *Client {
	client := &Client{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		userAgent:   "CompanyName <contact@email.com>",
		rateLimiter: rate.NewLimiter(rate.Limit(10), 10),
	}

	for _, option := range options {
		option(client)
	}
	return client
}

// WithHTTPClient allows custom HTTP client configuration
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithUserAgent sets a custom user agent string
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) {
		c.userAgent = userAgent
	}
}

// FileContents retrieves the contents of a file at the specified URL
func (c *Client) FileContents(ctx context.Context, url string) ([]byte, error) {
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// FilerMatch represents an entity name to CIK mapping
type FilerMatch struct {
	Name string `json:"name"`
	CIK  string `json:"cik"`
}

// FilerFilterOptions provides filtering options for filer searches
type FilerFilterOptions struct {
	Contains string   // Filter filer names containing this string (case-insensitive)
	CIKs     []string // Filter by specific CIK numbers
	Limit    int      // Limit number of results
}

// SearchFilers retrieves and filters filer names and CIK numbers
func (c *Client) SearchFilers(ctx context.Context, opts *FilerFilterOptions) ([]*FilerMatch, error) {
	resp, err := c.get(ctx, "https://www.sec.gov/Archives/edgar/cik-lookup-data.txt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	matches := make([]*FilerMatch, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}

		name := strings.TrimSpace(fields[0])
		cik := strings.TrimLeft(fields[1], "0")
		cik = fmt.Sprintf("%010s", cik)

		if opts != nil {
			if len(opts.CIKs) > 0 && !slices.Contains(opts.CIKs, cik) {
				continue
			}
			if opts.Contains != "" && !strings.Contains(
				strings.ToLower(name),
				strings.ToLower(opts.Contains),
			) {
				continue
			}
		}

		matches = append(matches, &FilerMatch{
			Name: name,
			CIK:  cik,
		})
	}

	if opts != nil && opts.Limit > 0 && len(matches) > opts.Limit {
		matches = matches[:opts.Limit]
	}
	return matches, nil
}

// CompanyMatch represents a company name to CIK mapping
type CompanyMatch struct {
	CIK          string `json:"cik"`
	Name         string `json:"name"`
	Ticker       string `json:"ticker"`
	ExchangeName string `json:"exchangeName"`
}

// CompanyFilterOptions provides filtering options for company tickers
type CompanyFilterOptions struct {
	Tickers   []string // Filter by specific ticker symbols
	CIKs      []string // Filter by specific CIK numbers
	Exchanges []string // Filter by specific exchanges
	Contains  string   // Filter company names containing this string (case-insensitive)
	Limit     int      // Limit the number of results
}

// SearchCompanies retrieves a list of company ticker symbols and exchange information
func (c *Client) SearchCompanies(ctx context.Context, opts *CompanyFilterOptions) ([]*CompanyMatch, error) {
	resp, err := c.get(ctx, "https://www.sec.gov/files/company_tickers_exchange.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var responseData struct {
		Fields []string `json:"fields"`
		Data   [][]any  `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	companies := make([]*CompanyMatch, 0, len(responseData.Data))
	for _, row := range responseData.Data {
		if len(row) != 4 {
			continue
		}

		cik, ok := row[0].(float64)
		if !ok {
			continue
		}
		cikStr := fmt.Sprintf("%010d", int(cik))

		name, ok := row[1].(string)
		if !ok {
			continue
		}

		ticker, ok := row[2].(string)
		if !ok {
			continue
		}

		exchange, ok := row[3].(string)
		if !ok {
			continue
		}

		if opts != nil {
			if len(opts.CIKs) > 0 && !slices.Contains(opts.CIKs, cikStr) {
				continue
			}
			if len(opts.Tickers) > 0 && !slices.Contains(opts.Tickers, ticker) {
				continue
			}
			if len(opts.Exchanges) > 0 && !slices.Contains(opts.Exchanges, exchange) {
				continue
			}
			if opts.Contains != "" && !strings.Contains(
				strings.ToLower(name),
				strings.ToLower(opts.Contains),
			) {
				continue
			}
		}
		companies = append(companies, &CompanyMatch{
			CIK:          cikStr,
			Name:         name,
			Ticker:       ticker,
			ExchangeName: exchange,
		})
	}

	if opts != nil && opts.Limit > 0 && len(companies) > opts.Limit {
		companies = companies[:opts.Limit]
	}
	return companies, nil
}

// DirectoryEntry represents a single file in a directory listing
type DirectoryEntry struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Size         int64     `json:"size,omitempty"`
}

// FilerDirectoryFilterOptions provides filtering options for index entries
type FilerDirectoryFilterOptions struct {
	StartDate time.Time // Filter entries modified after this date
	EndDate   time.Time // Filter entries modified before this date
	Limit     int       // Limit the number of results
}

// FilerDirectory retrieves the contents of a specific filer directory
func (c *Client) FilerDirectory(ctx context.Context, cik string, opts *FilerDirectoryFilterOptions) ([]*DirectoryEntry, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	url := fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/index.json", normalizedCIK)

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var directoryData struct {
		Directory struct {
			Items []struct {
				LastModified string `json:"last-modified"`
				Name         string `json:"name"`
				Size         string `json:"size"`
			} `json:"item"`
			Name      string `json:"name"`
			ParentDir string `json:"parent-dir"`
		} `json:"directory"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&directoryData); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	entries := make([]*DirectoryEntry, 0, len(directoryData.Directory.Items))
	for _, item := range directoryData.Directory.Items {
		modTime, err := time.Parse("2006-01-02 15:04:05", item.LastModified)
		if err != nil {
			continue
		}
		if opts != nil {
			if !opts.StartDate.IsZero() && modTime.Before(opts.StartDate) {
				continue
			}
			if !opts.EndDate.IsZero() && modTime.After(opts.EndDate) {
				continue
			}
		}

		size, _ := strconv.ParseInt(item.Size, 10, 64)

		entries = append(entries, &DirectoryEntry{
			LastModified: modTime,
			Name:         item.Name,
			Size:         size,
			URL:          fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s", normalizedCIK, item.Name),
		})
	}

	if opts != nil && opts.Limit > 0 && len(entries) > opts.Limit {
		entries = entries[:opts.Limit]
	}
	return entries, nil
}

// FilingDirectoryFilterOptions provides filtering options for filing directory entries
type FilingDirectoryFilterOptions struct {
	DocumentName  string // Filter by document name
	FileExtension string // Filter by document extension (e.g., ".htm", ".xml")
	Limit         int    // Limit the number of results
}

// FilingDirectory retrieves the contents of a specific filing directory
func (c *Client) FilingDirectory(ctx context.Context, cik string, accessionNumber string, opts *FilingDirectoryFilterOptions) ([]*DirectoryEntry, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	accessionNumber = strings.ReplaceAll(accessionNumber, "-", "")

	url := fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/index.json", normalizedCIK, accessionNumber)

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var filingDirectoryData struct {
		Directory struct {
			Items []struct {
				LastModified string `json:"last-modified"`
				Name         string `json:"name"`
				Size         string `json:"size"`
			} `json:"item"`
			Name      string `json:"name"`
			ParentDir string `json:"parent-dir"`
		} `json:"directory"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&filingDirectoryData); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	documents := make([]*DirectoryEntry, 0, len(filingDirectoryData.Directory.Items))
	for _, file := range filingDirectoryData.Directory.Items {
		if opts != nil {
			if opts.DocumentName != "" && !strings.Contains(strings.ToLower(file.Name), strings.ToLower(opts.DocumentName)) {
				continue
			}
			if opts.FileExtension != "" && !strings.HasSuffix(strings.ToLower(file.Name), strings.ToLower(opts.FileExtension)) {
				continue
			}
		}

		modTime, err := time.Parse("2006-01-02 15:04:05", file.LastModified)
		if err != nil {
			continue
		}

		size, _ := strconv.ParseInt(file.Size, 10, 64)

		documents = append(documents, &DirectoryEntry{
			LastModified: modTime,
			Name:         file.Name,
			Size:         size,
			URL:          fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/%s", normalizedCIK, accessionNumber, file.Name),
		})
	}

	if opts != nil && opts.Limit > 0 && len(documents) > opts.Limit {
		documents = documents[:opts.Limit]
	}
	return documents, nil
}

// Filer represents a filer's profile information
type Filer struct {
	CIK                  string   `json:"cik"`
	EntityType           string   `json:"entityType"`
	SIC                  string   `json:"sic"`
	SICDescription       string   `json:"sicDescription"`
	Name                 string   `json:"name"`
	Tickers              []string `json:"tickers"`
	Exchanges            []string `json:"exchanges"`
	EIN                  string   `json:"ein"`
	Description          string   `json:"description"`
	Website              string   `json:"website"`
	Category             string   `json:"category"`
	FiscalYearEnd        string   `json:"fiscalYearEnd"`
	StateOfIncorporation string   `json:"stateOfIncorporation"`
	PhoneNumber          string   `json:"phoneNumber"`
	Flags                string   `json:"flags"`
}

// Filer retrieves a filer's profile information
func (c *Client) Filer(ctx context.Context, cik string) (*Filer, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	filename := fmt.Sprintf("CIK%s.json", normalizedCIK)

	submissions, err := c.submissionsFile(ctx, filename)
	if err != nil {
		return nil, fmt.Errorf("fetching company data: %w", err)
	}

	return &Filer{
		CIK:                  submissions.CIK,
		EntityType:           submissions.EntityType,
		SIC:                  submissions.SIC,
		SICDescription:       submissions.SICDesc,
		Name:                 submissions.Name,
		Tickers:              submissions.Tickers,
		Exchanges:            submissions.Exchanges,
		EIN:                  submissions.EIN,
		Description:          submissions.Description,
		Website:              submissions.Website,
		Category:             submissions.Category,
		FiscalYearEnd:        submissions.FiscalYearEnd,
		StateOfIncorporation: submissions.StateOfIncorp,
		PhoneNumber:          submissions.Phone,
		Flags:                submissions.Flags,
	}, nil
}

// Filing represents a single filing submission
type Filing struct {
	AccessionNumber            string    `json:"accessionNumber"`
	Form                       string    `json:"form"`
	FilingDate                 time.Time `json:"filingDate"`
	ReportDate                 time.Time `json:"reportDate,omitempty"`
	AcceptanceTime             time.Time `json:"acceptanceDateTime"`
	Act                        string    `json:"act,omitempty"`
	Size                       int       `json:"size"`
	Items                      []string  `json:"items,omitempty"`
	IsXBRL                     bool      `json:"isXBRL"`
	IsInlineXBRL               bool      `json:"isInlineXBRL"`
	PrimaryDocument            string    `json:"primaryDocument"`
	PrimaryDocumentDescription string    `json:"primaryDocumentDescription"`
}

// FilingFilterOptions is used to filter filings
type FilingFilterOptions struct {
	StartDate time.Time
	EndDate   time.Time
	Forms     []string
	Limit     int
}

// Filings retrieves and filters filings for a given CIK
func (c *Client) Filings(ctx context.Context, cik string, opts *FilingFilterOptions) ([]*Filing, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	filename := fmt.Sprintf("CIK%s.json", normalizedCIK)

	mainSubmissions, err := c.submissionsFile(ctx, filename)
	if err != nil {
		return nil, fmt.Errorf("fetching main filings: %w", err)
	}

	allFilings := make([]*Filing, 0)
	mainFilings, err := parseFilings(mainSubmissions.Filings.Recent)
	if err != nil {
		return nil, fmt.Errorf("processing main filings: %w", err)
	}
	allFilings = append(allFilings, mainFilings...)

	for _, file := range mainSubmissions.Filings.Files {
		additionalSubmissions, err := c.submissionsFile(ctx, file.Name)
		if err != nil {
			return nil, fmt.Errorf("fetching additional filings file %s: %w", file.Name, err)
		}

		additionalFilings, err := parseFilings(additionalSubmissions.Filings.Recent)
		if err != nil {
			return nil, fmt.Errorf("processing additional filings from %s: %w", file.Name, err)
		}
		allFilings = append(allFilings, additionalFilings...)
	}

	var filtered []*Filing
	if opts != nil {
		for _, filing := range allFilings {
			if !opts.StartDate.IsZero() && filing.FilingDate.Before(opts.StartDate) {
				continue
			}
			if !opts.EndDate.IsZero() && filing.FilingDate.After(opts.EndDate) {
				continue
			}
			if len(opts.Forms) > 0 && !slices.Contains(opts.Forms, filing.Form) {
				continue
			}
			filtered = append(filtered, filing)
		}
		if opts.Limit > 0 && len(filtered) > opts.Limit {
			filtered = filtered[:opts.Limit]
		}
	} else {
		filtered = allFilings
	}
	return filtered, nil
}

type submissionsResponse struct {
	CIK           string   `json:"cik"`
	EntityType    string   `json:"entityType"`
	SIC           string   `json:"sic"`
	SICDesc       string   `json:"sicDescription"`
	Name          string   `json:"name"`
	Tickers       []string `json:"tickers"`
	Exchanges     []string `json:"exchanges"`
	EIN           string   `json:"ein"`
	Description   string   `json:"description"`
	Website       string   `json:"website"`
	Category      string   `json:"category"`
	FiscalYearEnd string   `json:"fiscalYearEnd"`
	StateOfIncorp string   `json:"stateOfIncorporation"`
	Phone         string   `json:"phone"`
	Flags         string   `json:"flags"`
	Filings       struct {
		Recent filingsData `json:"recent"`
		Files  []struct {
			Name        string `json:"name"`
			FilingCount int    `json:"filingCount"`
			FilingFrom  string `json:"filingFrom"`
			FilingTo    string `json:"filingTo"`
		} `json:"files"`
	} `json:"filings"`
}

type filingsData struct {
	AccessionNumbers []string `json:"accessionNumber"`
	Forms            []string `json:"form"`
	FilingDates      []string `json:"filingDate"`
	ReportDates      []string `json:"reportDate"`
	AcceptanceDates  []string `json:"acceptanceDateTime"`
	Act              []string `json:"act"`
	Size             []int    `json:"size"`
	Items            []string `json:"items"`
	IsXBRL           []int    `json:"isXBRL"`
	IsInlineXBRL     []int    `json:"isInlineXBRL"`
	PrimaryDoc       []string `json:"primaryDocument"`
	PrimaryDocDesc   []string `json:"primaryDocDescription"`
}

func parseFilings(recent filingsData) ([]*Filing, error) {
	filingCount := len(recent.AccessionNumbers)
	filings := make([]*Filing, 0, filingCount)

	for i := 0; i < filingCount; i++ {
		filing := &Filing{
			AccessionNumber: recent.AccessionNumbers[i],
			Form:            recent.Forms[i],
			Size:            recent.Size[i],
			IsXBRL:          recent.IsXBRL[i] == 1,
			IsInlineXBRL:    recent.IsInlineXBRL[i] == 1,
		}

		if recent.FilingDates[i] != "" {
			filingDate, err := time.Parse("2006-01-02", recent.FilingDates[i])
			if err != nil {
				return nil, fmt.Errorf("parsing filing date: %w", err)
			}
			filing.FilingDate = filingDate
		}

		if i < len(recent.ReportDates) && recent.ReportDates[i] != "" {
			reportDate, err := time.Parse("2006-01-02", recent.ReportDates[i])
			if err != nil {
				return nil, fmt.Errorf("parsing report date: %w", err)
			}
			filing.ReportDate = reportDate
		}

		if recent.AcceptanceDates[i] != "" {
			acceptanceTime, err := time.Parse(time.RFC3339, recent.AcceptanceDates[i])
			if err != nil {
				return nil, fmt.Errorf("parsing acceptance time: %w", err)
			}
			filing.AcceptanceTime = acceptanceTime
		}

		if i < len(recent.Act) {
			filing.Act = recent.Act[i]
		}
		if i < len(recent.Items) && recent.Items[i] != "" {
			filing.Items = strings.Split(recent.Items[i], ",")
			for j := range filing.Items {
				filing.Items[j] = strings.TrimSpace(filing.Items[j])
			}
		}
		if i < len(recent.PrimaryDoc) {
			filing.PrimaryDocument = recent.PrimaryDoc[i]
		}
		if i < len(recent.PrimaryDocDesc) {
			filing.PrimaryDocumentDescription = recent.PrimaryDocDesc[i]
		}

		filings = append(filings, filing)
	}
	return filings, nil
}

func (c *Client) submissionsFile(ctx context.Context, filename string) (*submissionsResponse, error) {
	url := fmt.Sprintf("https://data.sec.gov/submissions/%s", filename)

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var submissions submissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&submissions); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &submissions, nil
}

func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}
