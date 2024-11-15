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

// Directory represents a single file in a directory listing
type Directory struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	Link         string    `json:"link"`
}

// IndexFilter provides filtering options for index entries
type IndexFilter struct {
	StartDate  time.Time // Filter entries modified after this date
	EndDate    time.Time // Filter entries modified before this date
	MaxResults int       // Limit the number of results
}

// Index retrieves the directory listing for a given CIK
func (c *Client) Index(ctx context.Context, cik string, filter *IndexFilter) ([]*Directory, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	url := fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/index.json", normalizedCIK)

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
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

	entries := make([]*Directory, 0, len(indexDir.Directory.Items))
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
		entries = append(entries, &Directory{
			LastModified: modTime,
			Name:         item.Name,
			Link:         fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s", normalizedCIK, item.Name),
		})
	}

	if filter != nil && filter.MaxResults > 0 && len(entries) > filter.MaxResults {
		entries = entries[:filter.MaxResults]
	}
	return entries, nil
}

// File represents a single file in a filing directory
type File struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	Size         string    `json:"size"`
	Link         string    `json:"link"`
}

// FileFilter provides filtering options for filing directory entries
type FileFilter struct {
	Extension  string // Filter by file extension (e.g., ".htm", ".xml")
	MaxResults int    // Limit the number of results
}

// FilingContents retrieves the contents of a specific filing directory
func (c *Client) FilingContents(ctx context.Context, cik string, accessionNumber string, filter *FileFilter) ([]*File, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	accessionNumber = strings.ReplaceAll(accessionNumber, "-", "")

	url := fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/index.json", normalizedCIK, accessionNumber)

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
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

	files := make([]*File, 0, len(filingDir.Directory.Items))
	for _, file := range filingDir.Directory.Items {
		if filter != nil {
			if filter.Extension != "" && !strings.HasSuffix(strings.ToLower(file.Name), strings.ToLower(filter.Extension)) {
				continue
			}
		}
		modTime, err := time.Parse("2006-01-02 15:04:05", file.LastModified)
		if err != nil {
			continue
		}
		files = append(files, &File{
			LastModified: modTime,
			Name:         file.Name,
			Size:         file.Size,
			Link:         fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/%s", normalizedCIK, accessionNumber, file.Name),
		})
	}

	if filter != nil && filter.MaxResults > 0 && len(files) > filter.MaxResults {
		files = files[:filter.MaxResults]
	}
	return files, nil
}

// IndexEntry represents a single entry in the daily index directory
type IndexEntry struct {
	LastModified time.Time `json:"lastModified"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Size         string    `json:"size"`
	Link         string    `json:"link"`
}

// IndexScope represents the scope of the daily index request
type IndexScope struct {
	Year    int // Optional year to retrieve (e.g., 2024)
	Quarter int // Optional quarter to retrieve (must specify year)
}

// Validate checks if the scope is valid
func (s *IndexScope) Validate() error {
	if s.Quarter != 0 {
		if s.Year == 0 {
			return fmt.Errorf("year is required when quarter is specified")
		}
		if s.Quarter < 1 || s.Quarter > 4 {
			return fmt.Errorf("quarter must be between 1 and 4")
		}
	}
	return nil
}

// DailyIndex retrieves the daily index directory listing at the specified scope
func (c *Client) DailyIndex(ctx context.Context, scope *IndexScope) ([]*IndexEntry, error) {
	const baseURL = "https://www.sec.gov/Archives/edgar/daily-index"

	url := baseURL + "/index.json"

	if scope != nil {
		if err := scope.Validate(); err != nil {
			return nil, err
		}
		if scope.Year > 0 {
			yearStr := strconv.Itoa(scope.Year)
			if scope.Quarter > 0 {
				quarterStr := strconv.Itoa(scope.Quarter)
				url = fmt.Sprintf("%s/%s/QTR%s/index.json", baseURL, yearStr, quarterStr)
			} else {
				url = fmt.Sprintf("%s/%s/index.json", baseURL, yearStr)
			}
		}
	}

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
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

		link := baseURL
		if item.Type == "dir" {
			link = fmt.Sprintf("%s/%s/", baseURL, strings.TrimSuffix(item.Href, "/"))
		} else {
			link = fmt.Sprintf("%s/%s", baseURL, item.Href)
		}

		entries = append(entries, &IndexEntry{
			LastModified: modTime,
			Name:         item.Name,
			Type:         item.Type,
			Link:         link,
			Size:         item.Size,
		})
	}
	return entries, nil
}

// FullIndex retrieves the full index directory listing at the specified scope
func (c *Client) FullIndex(ctx context.Context, scope *IndexScope) ([]*IndexEntry, error) {
	const baseURL = "https://www.sec.gov/Archives/edgar/full-index"

	url := baseURL + "/index.json"

	if scope != nil {
		if err := scope.Validate(); err != nil {
			return nil, err
		}
		if scope.Year > 0 {
			yearStr := strconv.Itoa(scope.Year)
			if scope.Quarter > 0 {
				quarterStr := strconv.Itoa(scope.Quarter)
				url = fmt.Sprintf("%s/%s/QTR%s/index.json", baseURL, yearStr, quarterStr)
			} else {
				url = fmt.Sprintf("%s/%s/index.json", baseURL, yearStr)
			}
		}
	}

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
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

		link := baseURL
		if item.Type == "dir" {
			link = fmt.Sprintf("%s/%s/", baseURL, strings.TrimSuffix(item.Href, "/"))
		} else {
			link = fmt.Sprintf("%s/%s", baseURL, item.Href)
		}

		entries = append(entries, &IndexEntry{
			LastModified: modTime,
			Name:         item.Name,
			Type:         item.Type,
			Link:         link,
			Size:         item.Size,
		})
	}
	return entries, nil
}

// CompanyTicker represents a company ticker symbol
type CompanyTicker struct {
	CIK    string `json:"cik"`
	Ticker string `json:"ticker"`
	Title  string `json:"title"`
}

// String returns a string representation of the company ticker
func (ct CompanyTicker) String() string {
	return fmt.Sprintf("%010s    %-8s %-30s", ct.CIK, ct.Ticker, ct.Title)
}

// TickerFilter provides filtering options for company tickers
type TickerFilter struct {
	Tickers   []string // Filter by specific ticker symbols
	CIKs      []string // Filter by specific CIK numbers
	Contains  string   // Filter company names containing this string (case-insensitive)
	MaxResult int      // Limit the number of results
}

// CompanyTickers retrieves and optionally filters the list of company tickers
func (c *Client) CompanyTickers(ctx context.Context, filter *TickerFilter) ([]*CompanyTicker, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "https://www.sec.gov/files/company_tickers.json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rawResponse map[string]struct {
		CIK    int    `json:"cik_str"`
		Ticker string `json:"ticker"`
		Title  string `json:"title"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawResponse); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	companies := make([]*CompanyTicker, 0, len(rawResponse))
	for _, company := range rawResponse {
		cik := fmt.Sprintf("%010d", company.CIK)
		if filter != nil {
			if len(filter.CIKs) > 0 && !slices.Contains(filter.CIKs, cik) {
				continue
			}
			if len(filter.Tickers) > 0 && !slices.Contains(filter.Tickers, company.Ticker) {
				continue
			}
			if filter.Contains != "" && !strings.Contains(
				strings.ToLower(company.Title),
				strings.ToLower(filter.Contains),
			) {
				continue
			}
		}
		companies = append(companies, &CompanyTicker{
			CIK:    cik,
			Ticker: company.Ticker,
			Title:  company.Title,
		})
	}

	if filter != nil && filter.MaxResult > 0 && len(companies) > filter.MaxResult {
		companies = companies[:filter.MaxResult]
	}
	return companies, nil
}

// CompanyTickerExchange represents a company ticker symbol with exchange information
type CompanyTickerExchange struct {
	CIK      string `json:"cik"`
	Name     string `json:"name"`
	Ticker   string `json:"ticker"`
	Exchange string `json:"exchange"`
}

// String returns a string representation of the company ticker with exchange
func (cte CompanyTickerExchange) String() string {
	return fmt.Sprintf("%010s    %-8s %-10s %-10s", cte.CIK, cte.Ticker, cte.Exchange, cte.Name)
}

// ExchangeFilter provides filtering options for exchange tickers
type ExchangeFilter struct {
	Tickers    []string // Filter by specific ticker symbols
	CIKs       []string // Filter by specific CIK numbers
	Exchanges  []string // Filter by specific exchanges
	Contains   string   // Filter company names containing this string (case-insensitive)
	MaxResults int      // Limit the number of results
}

// CompanyTickersWithExchange retrieves and optionally filters the list of exchange tickers
func (c *Client) CompanyTickersWithExchange(ctx context.Context, filter *ExchangeFilter) ([]*CompanyTickerExchange, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "https://www.sec.gov/files/company_tickers_exchange.json", nil)
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

	companies := make([]*CompanyTickerExchange, 0, len(rawResponse.Data))
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
		companies = append(companies, &CompanyTickerExchange{
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

// MutualFundTicker represents a mutual fund ticker symbol
type MutualFundTicker struct {
	CIK      string `json:"cik"`
	SeriesID string `json:"seriesId"`
	ClassID  string `json:"classId"`
	Ticker   string `json:"symbol"`
}

// String returns a string representation of the mutual fund ticker
func (ctmf MutualFundTicker) String() string {
	return fmt.Sprintf("%010s    %-12s %-12s %-8s", ctmf.CIK, ctmf.SeriesID, ctmf.ClassID, ctmf.Ticker)
}

// MutualFundFilter provides filtering options for mutual fund tickers
type MutualFundFilter struct {
	Tickers    []string // Filter by specific ticker symbols
	CIKs       []string // Filter by specific CIK numbers
	SeriesIDs  []string // Filter by specific series IDs
	ClassIDs   []string // Filter by specific class IDs
	MaxResults int      // Limit the number of results
}

// MutualFundTickers retrieves and optionally filters the list of mutual fund tickers
func (c *Client) MutualFundTickers(ctx context.Context, filter *MutualFundFilter) ([]*MutualFundTicker, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "https://www.sec.gov/files/company_tickers_mf.json", nil)
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

	funds := make([]*MutualFundTicker, 0, len(rawResponse.Data))
	for _, row := range rawResponse.Data {
		if len(row) != 4 {
			continue
		}

		cik, ok := row[0].(float64)
		if !ok {
			continue
		}
		cikStr := fmt.Sprintf("%010d", int(cik))

		seriesID, ok := row[1].(string)
		if !ok {
			continue
		}

		classID, ok := row[2].(string)
		if !ok {
			continue
		}

		symbol, ok := row[3].(string)
		if !ok {
			continue
		}

		if filter != nil {
			if len(filter.CIKs) > 0 && !slices.Contains(filter.CIKs, cikStr) {
				continue
			}
			if len(filter.Tickers) > 0 && !slices.Contains(filter.Tickers, symbol) {
				continue
			}
			if len(filter.SeriesIDs) > 0 && !slices.Contains(filter.SeriesIDs, seriesID) {
				continue
			}
			if len(filter.ClassIDs) > 0 && !slices.Contains(filter.ClassIDs, classID) {
				continue
			}
		}
		funds = append(funds, &MutualFundTicker{
			CIK:      cikStr,
			SeriesID: seriesID,
			ClassID:  classID,
			Ticker:   symbol,
		})
	}

	if filter != nil && filter.MaxResults > 0 && len(funds) > filter.MaxResults {
		funds = funds[:filter.MaxResults]
	}
	return funds, nil
}

// Company represents a company's information from SEC submissions
type Company struct {
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
}

// Company retrieves company information for a given CIK
func (c *Client) Company(ctx context.Context, cik string) (*Company, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	filename := fmt.Sprintf("CIK%s.json", normalizedCIK)

	submissions, err := c.fetchSubmissionsFile(ctx, filename)
	if err != nil {
		return nil, fmt.Errorf("fetching company data: %w", err)
	}

	return &Company{
		CIK:           submissions.CIK,
		EntityType:    submissions.EntityType,
		SIC:           submissions.SIC,
		SICDesc:       submissions.SICDesc,
		Name:          submissions.Name,
		Tickers:       submissions.Tickers,
		Exchanges:     submissions.Exchanges,
		EIN:           submissions.EIN,
		Description:   submissions.Description,
		Website:       submissions.Website,
		Category:      submissions.Category,
		FiscalYearEnd: submissions.FiscalYearEnd,
		StateOfIncorp: submissions.StateOfIncorp,
		Phone:         submissions.Phone,
		Flags:         submissions.Flags,
	}, nil
}

// Filing represents a single filing submission
type Filing struct {
	AccessionNumber string    `json:"accessionNumber"`
	Form            string    `json:"form"`
	FilingDate      time.Time `json:"filingDate"`
	ReportDate      time.Time `json:"reportDate,omitempty"`
	AcceptanceTime  time.Time `json:"acceptanceDateTime"`
	Act             string    `json:"act,omitempty"`
	Size            int       `json:"size"`
	Items           []string  `json:"items,omitempty"`
	IsXBRL          bool      `json:"isXBRL"`
	IsInlineXBRL    bool      `json:"isInlineXBRL"`
	PrimaryDocument string    `json:"primaryDocument"`
	PrimaryDocDesc  string    `json:"primaryDocDescription"`
}

// FilingFilter is used to filter filings
type FilingFilter struct {
	StartDate  time.Time
	EndDate    time.Time
	Forms      []string
	MaxResults int
}

// Filings retrieves and filters filings for a given CIK
func (c *Client) Filings(ctx context.Context, cik string, filter *FilingFilter) ([]*Filing, error) {
	normalizedCIK := fmt.Sprintf("%010s", strings.TrimLeft(cik, "0"))
	filename := fmt.Sprintf("CIK%s.json", normalizedCIK)

	mainSubmissions, err := c.fetchSubmissionsFile(ctx, filename)
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
		additionalSubmissions, err := c.fetchSubmissionsFile(ctx, file.Name)
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
			filing.PrimaryDocDesc = recent.PrimaryDocDesc[i]
		}

		filings = append(filings, filing)
	}
	return filings, nil
}

func (c *Client) fetchSubmissionsFile(ctx context.Context, filename string) (*rawSubmissions, error) {
	url := fmt.Sprintf("https://data.sec.gov/submissions/%s", filename)

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
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

func (c *Client) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
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
