package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adrg/xdg"
	"github.com/gptscript-ai/go-gptscript"
)

type oauthResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type cred struct {
	Env          map[string]string `json:"env"`
	ExpiresAt    *time.Time        `json:"expiresAt"`
	RefreshToken string            `json:"refreshToken"`
}

type cliConfig struct {
	Integrations map[string]string `json:"integrations"`
	GatewayURL   string            `json:"gatewayURL"`
}

var (
	integration = os.Getenv("INTEGRATION")
	env         = os.Getenv("ENV")
	scope       = os.Getenv("SCOPE")
)

func main() {
	configPath, err := xdg.ConfigFile("gptscript/config.json")
	if err != nil {
		fmt.Printf("failed to get config file: %v\n", err)
		os.Exit(1)
	}

	if os.Getenv("GPTSCRIPT_CONFIG") != "" {
		configPath = os.Getenv("GPTSCRIPT_CONFIG")
	}

	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("failed to read config file: %v\n", err)
		os.Exit(1)
	}

	var cfg cliConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		fmt.Printf("failed to unmarshal config: %v\n", err)
		os.Exit(1)
	}

	integrationAppID, ok := cfg.Integrations[integration]
	if !ok {
		fmt.Printf("integration %q not found\n", integration)
		os.Exit(1)
	}

	var (
		authorizeURL = fmt.Sprintf("%s/oauth-apps/%s/authorize", cfg.GatewayURL, integrationAppID)
		refreshURL   = fmt.Sprintf("%s/oauth-apps/%s/refresh", cfg.GatewayURL, integrationAppID)
		tokenURL     = fmt.Sprintf("%s/api/oauth-apps/get-token", cfg.GatewayURL)
	)

	// Refresh existing credential if there is one.
	existing := os.Getenv("GPTSCRIPT_EXISTING_CREDENTIAL")
	if existing != "" {
		var c cred
		if err := json.Unmarshal([]byte(existing), &c); err != nil {
			fmt.Printf("failed to unmarshal existing credential: %v\n", err)
			os.Exit(1)
		}

		u, err := url.Parse(refreshURL)
		if err != nil {
			fmt.Printf("failed to parse URL: %v\n", err)
			os.Exit(1)
		}

		q := u.Query()
		q.Set("refresh_token", c.RefreshToken)
		if scope != "" {
			q.Set("scope", scope)
		}
		u.RawQuery = q.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			fmt.Printf("failed to create request: %v\n", err)
			os.Exit(1)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Printf("failed to send request: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("unexpected status code: %d\n", resp.StatusCode)
			os.Exit(1)
		}

		var oauthResp oauthResponse
		if err := json.NewDecoder(resp.Body).Decode(&oauthResp); err != nil {
			fmt.Printf("failed to decode JSON: %v\n", err)
			os.Exit(1)
		}

		out := cred{
			Env: map[string]string{
				env: oauthResp.AccessToken,
			},
			RefreshToken: oauthResp.RefreshToken,
		}

		if oauthResp.ExpiresIn > 0 {
			expiresAt := time.Now().Add(time.Second * time.Duration(oauthResp.ExpiresIn))
			out.ExpiresAt = &expiresAt
		}

		credJSON, err := json.Marshal(out)
		if err != nil {
			fmt.Printf("failed to marshal credential: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(string(credJSON))
		return
	}

	sigCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
	defer cancel()

	state, err := generateString()
	if err != nil {
		fmt.Printf("failed to generate state: %v\n", err)
		os.Exit(1)
	}

	verifier, err := generateString()
	if err != nil {
		fmt.Printf("failed to generate verifier: %v\n", err)
		os.Exit(1)
	}

	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := hex.EncodeToString(h.Sum(nil))

	u, err := url.Parse(authorizeURL)
	if err != nil {
		fmt.Printf("failed to parse URL: %v\n", err)
		os.Exit(1)
	}

	q := u.Query()
	q.Set("state", state)
	q.Set("challenge", challenge)
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	gs, err := gptscript.NewGPTScript(gptscript.GlobalOptions{})
	if err != nil {
		fmt.Printf("failed to create GPTScript: %v\n", err)
		os.Exit(1)
	}

	sysPromptInput := fmt.Sprintf(`{"message":%q,"fields":""}`, fmt.Sprintf("Please go to %s to authorize GPTScript.", u.String()))

	run, err := gs.Run(context.Background(), "sys.prompt", gptscript.Options{
		Input: sysPromptInput,
	})
	if err != nil {
		fmt.Printf("failed to run sys.prompt: %v\n", err)
		os.Exit(1)
	}

	if _, err = run.Text(); err != nil {
		fmt.Printf("failed to get text: %v\n", err)
		os.Exit(1)
	}

	t := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-sigCtx.Done():
			fmt.Println("canceled")
			os.Exit(1)
		case <-t.C:
			// Construct the request to get the token from the gateway.
			req, err := http.NewRequest("GET", tokenURL, nil)
			if err != nil {
				fmt.Printf("failed to create request: %v\n", err)
				os.Exit(1)
			}

			q = req.URL.Query()
			q.Set("state", state)
			q.Set("verifier", verifier)
			req.URL.RawQuery = q.Encode()

			// Send the request to the gateway.
			now := time.Now()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to send request: %v\n", err)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				fmt.Fprintf(os.Stderr, "unexpected status code: %d\n", resp.StatusCode)
				continue
			}

			// Parse the response from the gateway.
			var oauthResp oauthResponse
			if err := json.NewDecoder(resp.Body).Decode(&oauthResp); err != nil {
				fmt.Printf("failed to decode JSON: %v\n", err)
				_ = resp.Body.Close()
				os.Exit(1)
			}
			_ = resp.Body.Close()

			out := cred{
				Env: map[string]string{
					env: oauthResp.AccessToken,
				},
				RefreshToken: oauthResp.RefreshToken,
			}

			if oauthResp.ExpiresIn > 0 {
				expiresAt := now.Add(time.Second * time.Duration(oauthResp.ExpiresIn))
				out.ExpiresAt = &expiresAt
			}

			credJSON, err := json.Marshal(out)
			if err != nil {
				fmt.Printf("failed to marshal credential: %v\n", err)
				os.Exit(1)
			}

			fmt.Print(string(credJSON))
			os.Exit(0)
		}
	}
}

func generateString() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 256)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}
