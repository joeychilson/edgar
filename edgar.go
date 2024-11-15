package edgar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
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

// IndexEntry represents a single entry in the daily index directory
type IndexEntry struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Size         string    `json:"size"`
	Url          string    `json:"url"`
}

func validateDailyIndexRange(year, quarter int) error {
	currentYear := time.Now().Year()
	currentQuarter := (int(time.Now().Month())-1)/3 + 1

	if year < 1994 || year > currentYear {
		return fmt.Errorf("year must be between 1994 and %d", currentYear)
	}

	if quarter < 1 || quarter > 4 {
		return fmt.Errorf("quarter must be between 1 and 4")
	}

	if year == 1994 && quarter < 3 {
		return fmt.Errorf("for 1994, quarter must be 3 or 4")
	}

	if year == currentYear && quarter > currentQuarter {
		return fmt.Errorf("cannot request future quarter %d for year %d", quarter, year)
	}
	return nil
}

// DailyIndex retrieves the daily filings index directory listing for a specific year and quarter
func (c *Client) DailyIndex(ctx context.Context, year, quarter int) ([]*IndexEntry, error) {
	if err := validateDailyIndexRange(year, quarter); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%d/QTR%d", "https://www.sec.gov/Archives/edgar/daily-index", year, quarter)

	resp, err := c.get(ctx, fmt.Sprintf("%s/index.json", url))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var indexDir struct {
		Directory struct {
			Items []struct {
				LastModified string `json:"last-modified"`
				Name         string `json:"name"`
				Type         string `json:"type"`
				Href         string `json:"href"`
				Size         string `json:"size"`
			} `json:"item"`
			Name      string `json:"name"`
			ParentDir string `json:"parent-dir"`
		} `json:"directory"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&indexDir); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	entries := make([]*IndexEntry, 0, len(indexDir.Directory.Items))
	for _, item := range indexDir.Directory.Items {
		modTime, err := time.Parse("01/02/2006 03:04:05 PM", item.LastModified)
		if err != nil {
			continue
		}

		entries = append(entries, &IndexEntry{
			LastModified: modTime,
			Name:         item.Name,
			Type:         item.Type,
			Url:          fmt.Sprintf("%s/%s", url, item.Href),
			Size:         item.Size,
		})
	}
	return entries, nil
}

func validateFullIndexRange(year, quarter int) error {
	currentYear := time.Now().Year()
	currentQuarter := (int(time.Now().Month())-1)/3 + 1

	if year < 1993 || year > currentYear {
		return fmt.Errorf("year must be between 1993 and %d", currentYear)
	}

	if quarter < 1 || quarter > 4 {
		return fmt.Errorf("quarter must be between 1 and 4")
	}

	if year == currentYear && quarter > currentQuarter {
		return fmt.Errorf("cannot request future quarter %d for year %d", quarter, quarter)
	}
	return nil
}

// FullIndex retrieves the full index directory listing for a specific year and quarter
func (c *Client) FullIndex(ctx context.Context, year, quarter int) ([]*IndexEntry, error) {
	if err := validateFullIndexRange(year, quarter); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%d/QTR%d", "https://www.sec.gov/Archives/edgar/full-index", year, quarter)

	resp, err := c.get(ctx, fmt.Sprintf("%s/index.json", url))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var indexDir struct {
		Directory struct {
			Items []struct {
				LastModified string `json:"last-modified"`
				Name         string `json:"name"`
				Type         string `json:"type"`
				Href         string `json:"href"`
				Size         string `json:"size"`
			} `json:"item"`
			Name      string `json:"name"`
			ParentDir string `json:"parent-dir"`
		} `json:"directory"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&indexDir); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	entries := make([]*IndexEntry, 0, len(indexDir.Directory.Items))
	for _, item := range indexDir.Directory.Items {
		modTime, err := time.Parse("01/02/2006 03:04:05 PM", item.LastModified)
		if err != nil {
			continue
		}

		entries = append(entries, &IndexEntry{
			LastModified: modTime,
			Name:         item.Name,
			Type:         item.Type,
			Url:          fmt.Sprintf("%s/%s", url, item.Href),
			Size:         item.Size,
		})
	}
	return entries, nil
}

// Company represents a company ticker symbol with exchange information
type Company struct {
	CIK      string `json:"cik"`
	Name     string `json:"name"`
	Ticker   string `json:"ticker"`
	Exchange string `json:"exchange"`
}

// String returns a string representation of the company ticker with exchange
func (cte Company) String() string {
	return fmt.Sprintf("%010s    %-8s %-10s %-10s", cte.CIK, cte.Ticker, cte.Exchange, cte.Name)
}

// CompanyListFilter provides filtering options for company tickers
type CompanyListFilter struct {
	Tickers    []string // Filter by specific ticker symbols
	CIKs       []string // Filter by specific CIK numbers
	Exchanges  []string // Filter by specific exchanges
	Contains   string   // Filter company names containing this string (case-insensitive)
	MaxResults int      // Limit the number of results
}

// CompanyList retrieves and optionally filters the list of company tickers
func (c *Client) CompanyList(ctx context.Context, filter *CompanyListFilter) ([]*Company, error) {
	resp, err := c.get(ctx, "https://www.sec.gov/files/company_tickers_exchange.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawResponse struct {
		Fields []string `json:"fields"`
		Data   [][]any  `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawResponse); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	companies := make([]*Company, 0, len(rawResponse.Data))
	for _, row := range rawResponse.Data {
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

		if filter != nil {
			if len(filter.CIKs) > 0 && !slices.Contains(filter.CIKs, cikStr) {
				continue
			}
			if len(filter.Tickers) > 0 && !slices.Contains(filter.Tickers, ticker) {
				continue
			}
			if len(filter.Exchanges) > 0 && !slices.Contains(filter.Exchanges, exchange) {
				continue
			}
			if filter.Contains != "" && !strings.Contains(
				strings.ToLower(name),
				strings.ToLower(filter.Contains),
			) {
				continue
			}
		}
		companies = append(companies, &Company{
			CIK:      cikStr,
			Name:     name,
			Ticker:   ticker,
			Exchange: exchange,
		})
	}

	if filter != nil && filter.MaxResults > 0 && len(companies) > filter.MaxResults {
		companies = companies[:filter.MaxResults]
	}
	return companies, nil
}

// DirectoryEntry represents a single file in a directory listing
type DirectoryEntry struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	Url          string    `json:"url"`
}

// DirectoryFilter provides filtering options for index entries
type DirectoryFilter struct {
	StartDate  time.Time // Filter entries modified after this date
	EndDate    time.Time // Filter entries modified before this date
	MaxResults int       // Limit the number of results
}

// CompanyDirectory retrieves the contents of a company filing directory
func (c *Client) CompanyDirectory(ctx context.Context, cik string, filter *DirectoryFilter) ([]*DirectoryEntry, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	url := fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/index.json", normalizedCIK)

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var indexDir struct {
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
	if err := json.NewDecoder(resp.Body).Decode(&indexDir); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	entries := make([]*DirectoryEntry, 0, len(indexDir.Directory.Items))
	for _, item := range indexDir.Directory.Items {
		modTime, err := time.Parse("2006-01-02 15:04:05", item.LastModified)
		if err != nil {
			continue
		}
		if filter != nil {
			if !filter.StartDate.IsZero() && modTime.Before(filter.StartDate) {
				continue
			}
			if !filter.EndDate.IsZero() && modTime.After(filter.EndDate) {
				continue
			}
		}
		entries = append(entries, &DirectoryEntry{
			LastModified: modTime,
			Name:         item.Name,
			Url:          fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s", normalizedCIK, item.Name),
		})
	}

	if filter != nil && filter.MaxResults > 0 && len(entries) > filter.MaxResults {
		entries = entries[:filter.MaxResults]
	}
	return entries, nil
}

// FilingDocument represents a single file in a filing directory
type FilingDocument struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	Size         string    `json:"size"`
	Url          string    `json:"url"`
}

// DocumentFilter provides filtering options for filing directory entries
type DocumentFilter struct {
	Document   string // Filter by document name
	Extension  string // Filter by document extension (e.g., ".htm", ".xml")
	MaxResults int    // Limit the number of results
}

// FilingDocuments retrieves the contents of a specific filing directory
func (c *Client) FilingDocuments(ctx context.Context, cik string, accessionNumber string, filter *DocumentFilter) ([]*FilingDocument, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	accessionNumber = strings.ReplaceAll(accessionNumber, "-", "")

	url := fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/index.json", normalizedCIK, accessionNumber)

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var filingDir struct {
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
	if err := json.NewDecoder(resp.Body).Decode(&filingDir); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	files := make([]*FilingDocument, 0, len(filingDir.Directory.Items))
	for _, file := range filingDir.Directory.Items {
		if filter != nil {
			if filter.Document != "" && !strings.Contains(strings.ToLower(file.Name), strings.ToLower(filter.Document)) {
				continue
			}
			if filter.Extension != "" && !strings.HasSuffix(strings.ToLower(file.Name), strings.ToLower(filter.Extension)) {
				continue
			}
		}
		modTime, err := time.Parse("2006-01-02 15:04:05", file.LastModified)
		if err != nil {
			continue
		}
		files = append(files, &FilingDocument{
			LastModified: modTime,
			Name:         file.Name,
			Size:         file.Size,
			Url:          fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/%s", normalizedCIK, accessionNumber, file.Name),
		})
	}

	if filter != nil && filter.MaxResults > 0 && len(files) > filter.MaxResults {
		files = files[:filter.MaxResults]
	}
	return files, nil
}

// CompanyProfile represents a company's information from SEC submissions
type CompanyProfile struct {
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
	Phone                string   `json:"phone"`
	Flags                string   `json:"flags"`
}

// CompanyProfile retrieves company information for a given CIK
func (c *Client) CompanyProfile(ctx context.Context, cik string) (*CompanyProfile, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	filename := fmt.Sprintf("CIK%s.json", normalizedCIK)

	submissions, err := c.submissionsFile(ctx, filename)
	if err != nil {
		return nil, fmt.Errorf("fetching company data: %w", err)
	}

	return &CompanyProfile{
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
		Phone:                submissions.Phone,
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

// FilingFilter is used to filter filings
type FilingFilter struct {
	StartDate  time.Time
	EndDate    time.Time
	Forms      []string
	MaxResults int
}

// CompanyFilings retrieves and filters filings for a given CIK
func (c *Client) CompanyFilings(ctx context.Context, cik string, filter *FilingFilter) ([]*Filing, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	filename := fmt.Sprintf("CIK%s.json", normalizedCIK)

	mainSubmissions, err := c.submissionsFile(ctx, filename)
	if err != nil {
		return nil, fmt.Errorf("fetching main filings: %w", err)
	}

	allFilings := make([]*Filing, 0)
	mainFilings, err := processFilings(mainSubmissions.Filings.Recent)
	if err != nil {
		return nil, fmt.Errorf("processing main filings: %w", err)
	}
	allFilings = append(allFilings, mainFilings...)

	for _, file := range mainSubmissions.Filings.Files {
		additionalSubmissions, err := c.submissionsFile(ctx, file.Name)
		if err != nil {
			return nil, fmt.Errorf("fetching additional filings file %s: %w", file.Name, err)
		}

		additionalFilings, err := processFilings(additionalSubmissions.Filings.Recent)
		if err != nil {
			return nil, fmt.Errorf("processing additional filings from %s: %w", file.Name, err)
		}
		allFilings = append(allFilings, additionalFilings...)
	}

	var filtered []*Filing
	if filter != nil {
		for _, filing := range allFilings {
			if !filter.StartDate.IsZero() && filing.FilingDate.Before(filter.StartDate) {
				continue
			}
			if !filter.EndDate.IsZero() && filing.FilingDate.After(filter.EndDate) {
				continue
			}
			if len(filter.Forms) > 0 && !slices.Contains(filter.Forms, filing.Form) {
				continue
			}
			filtered = append(filtered, filing)
		}
		if filter.MaxResults > 0 && len(filtered) > filter.MaxResults {
			filtered = filtered[:filter.MaxResults]
		}
	} else {
		filtered = allFilings
	}
	return filtered, nil
}

type rawSubmissions struct {
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
		Recent rawFilings `json:"recent"`
		Files  []struct {
			Name        string `json:"name"`
			FilingCount int    `json:"filingCount"`
			FilingFrom  string `json:"filingFrom"`
			FilingTo    string `json:"filingTo"`
		} `json:"files"`
	} `json:"filings"`
}

type rawFilings struct {
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

func processFilings(recent rawFilings) ([]*Filing, error) {
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

func (c *Client) submissionsFile(ctx context.Context, filename string) (*rawSubmissions, error) {
	url := fmt.Sprintf("https://data.sec.gov/submissions/%s", filename)

	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var submissions rawSubmissions
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
