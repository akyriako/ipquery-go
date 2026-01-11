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

type Client struct {
	httpClient *http.Client
	ipqueryUrl string
	username   string
	password   string
}

func NewClient(ipqueryUrl, username, password string) (*Client, error) {
	_, err := url.Parse(ipqueryUrl)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpClient: &http.Client{Timeout: 350 * time.Millisecond},
		ipqueryUrl: ipqueryUrl,
		username:   username,
		password:   password,
	}, nil
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
	req, err := http.NewRequest(http.MethodGet, c.ipqueryUrl, nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(
		c.username,
		c.password,
	)
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
