package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	defaultRepository = "ghcr.io/fystack/cosigner"
	registryBodyMax   = 4 << 20
	registryPagesMax  = 50
)

var stableTag = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var authParam = regexp.MustCompile(`(\w+)="([^"]*)"`)
var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// newestRelease only picks a candidate; the image is still signature- and
// contract-verified before it is pinned or executed.
func (a *App) newestRelease(ctx context.Context, repository string) (string, error) {
	tags, err := a.Tags(ctx, repository)
	if err != nil {
		return "", fmt.Errorf("list %s releases: %w", repository, err)
	}
	newest := ""
	for _, tag := range tags {
		if stableTag.MatchString(tag) && (newest == "" || stableVersionAfter(tag, newest)) {
			newest = tag
		}
	}
	if newest == "" {
		return "", fmt.Errorf("no stable Cosigner release found in %s", repository)
	}
	return newest, nil
}

// notifyUpdate is best-effort and never blocks or fails the calling command.
func (a *App) notifyUpdate(ctx context.Context, s Settings) {
	if a.Tags == nil || a.Getenv("COSIGNER_NO_UPDATE_CHECK") == "1" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	repository, _, _ := strings.Cut(s.Image, "@")
	newest, err := a.newestRelease(ctx, repository)
	if err != nil || !stableVersionAfter(newest, s.RuntimeVersion) {
		return
	}
	fmt.Fprintf(a.Err, "==> Update available: v%s → v%s (run `cosigner-cli update`)\n", strings.TrimPrefix(s.RuntimeVersion, "v"), strings.TrimPrefix(newest, "v"))
}

// registryTags lists tags through the OCI distribution API, fetching an
// anonymous pull token when the registry asks for one.
func registryTags(ctx context.Context, repository string) ([]string, error) {
	host, path := splitRepository(repository)
	client := &http.Client{Timeout: 15 * time.Second}
	next := "https://" + host + "/v2/" + path + "/tags/list?n=1000"
	token := ""
	var tags []string
	for page := 0; next != "" && page < registryPagesMax; page++ {
		resp, err := registryGet(ctx, client, next, token)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && token == "" {
			challenge := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			if token, err = anonymousToken(ctx, client, challenge); err != nil {
				return nil, err
			}
			page--
			continue
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		err = decodeRegistry(resp, &body)
		if err != nil {
			return nil, err
		}
		tags = append(tags, body.Tags...)
		next, err = nextPage(next, resp.Header.Get("Link"))
		if err != nil {
			return nil, err
		}
	}
	return tags, nil
}

func splitRepository(repository string) (host, path string) {
	first, rest, found := strings.Cut(repository, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first, rest
	}
	if !found {
		repository = "library/" + repository
	}
	return "registry-1.docker.io", repository
}

func registryGet(ctx context.Context, client *http.Client, target, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
}

func decodeRegistry(resp *http.Response, into any) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry returned %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, registryBodyMax)).Decode(into)
}

func anonymousToken(ctx context.Context, client *http.Client, challenge string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New("registry requires unsupported authentication")
	}
	values := map[string]string{}
	for _, match := range authParam.FindAllStringSubmatch(params, -1) {
		values[match[1]] = match[2]
	}
	realm, err := url.Parse(values["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" {
		return "", errors.New("registry token endpoint must use HTTPS")
	}
	query := realm.Query()
	for _, key := range []string{"service", "scope"} {
		if values[key] != "" {
			query.Set(key, values[key])
		}
	}
	realm.RawQuery = query.Encode()
	resp, err := registryGet(ctx, client, realm.String(), "")
	if err != nil {
		return "", err
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := decodeRegistry(resp, &body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("registry returned no pull token")
}

// nextPage keeps pagination on the original registry host.
func nextPage(current, link string) (string, error) {
	match := linkNext.FindStringSubmatch(link)
	if match == nil {
		return "", nil
	}
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	next, err := base.Parse(match[1])
	if err != nil {
		return "", err
	}
	if next.Scheme != base.Scheme || next.Host != base.Host {
		return "", errors.New("registry pagination left the registry host")
	}
	return next.String(), nil
}
