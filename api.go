package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

const speculusBase = "https://api.speculus.co"

func FetchSpeculus(client *http.Client, token string, ip net.IP) (Response, error) {
	var out Response

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/%s", speculusBase, ip), nil)
	if err != nil {
		return out, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("decode: %w (body: %s)", err, string(body))
	}
	return out, nil
}

func FetchHealth(client *http.Client) error {
	resp, err := client.Get(speculusBase + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func FetchQuota(client *http.Client, token string) (Quota, error) {
	var q Quota
	req, err := http.NewRequest("GET", speculusBase+"/v1/quota", nil)
	if err != nil {
		return q, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return q, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return q, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return q, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &q); err != nil {
		return q, fmt.Errorf("decode: %w (body: %s)", err, string(body))
	}
	return q, nil
}
