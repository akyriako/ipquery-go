package ipquerygo

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ifconfigMeIpAddressUrl = "https://ifconfig.me/ip"
)

var (
	defaultTimeout = 350 * time.Millisecond
)

type Client struct {
	httpClient *http.Client
	ipqueryURL string
	username   string
	password   string
}

type Option func(*Client) error

func NewClient(ipqueryURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(ipqueryURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid ipquery service url: %q", ipqueryURL)
	}

	c := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		ipqueryURL: ipqueryURL,
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if c.httpClient == nil {
		return nil, fmt.Errorf("http client cannot be nil")
	}
	if c.httpClient.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be > 0. timeout=%s", c.httpClient.Timeout)
	}
	if (c.username == "") != (c.password == "") {
		return nil, fmt.Errorf("basic auth requires both username and password")
	}

	return c, nil
}

func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return fmt.Errorf("timeout must be > 0, got %s", d)
		}
		if c.httpClient == nil {
			c.httpClient = &http.Client{}
		}
		c.httpClient.Timeout = d
		return nil
	}
}

func WithBasicAuth(username, password string) Option {
	return func(c *Client) error {
		if username == "" || password == "" {
			return fmt.Errorf("username and password must both be non-empty")
		}
		c.username = username
		c.password = password
		return nil
	}
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) error {
		if hc == nil {
			return fmt.Errorf("http client cannot be nil")
		}
		c.httpClient = hc
		return nil
	}
}

func (c *Client) GetOwnIP() (string, string, error) {
	ip, err := c.getOwnIP()
	if err != nil {
		ip, err := c.getOwnIPFallback()
		return ip, "ifconfig.me", err
	}

	return ip, "github.com/akyriako/ipquery-go", nil
}

func (c *Client) getOwnIP() (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.ipqueryURL, nil)
	if err != nil {
		return "", err
	}

	if (c.username != "") && (c.password != "") {
		req.SetBasicAuth(
			c.username,
			c.password,
		)
	}

	req.Header.Set("Content-Type", "application/text")

	httpResponse, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != 200 {
		return "", fmt.Errorf("http status %d", httpResponse.StatusCode)
	}

	httpBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return "", err
	}

	ipStr := string(httpBody)
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", fmt.Errorf("failed to parse ip address")
	}
	// Normalize IPv4-in-IPv6 form
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), nil
	}

	return ipStr, nil
}

func (c *Client) getOwnIPFallback() (string, error) {
	httpResponse, err := c.httpClient.Get(ifconfigMeIpAddressUrl)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != 200 {
		return "", fmt.Errorf("http status %d", httpResponse.StatusCode)
	}

	httpBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return "", err
	}

	return string(httpBody), nil
}
