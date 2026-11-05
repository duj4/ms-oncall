package harness

// Bounded observation of the isolated smoke SMTP sink for outbound isolation
// regressions. These helpers never contact a production provider.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (h *Harness) D08T1Sink() ([]byte, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + h.email.mp.apiAddr + "/api/v1/messages")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sink list status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (h *Harness) D08T1Consume(to, summary, details string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		raw, err := h.D08T1Sink()
		if err != nil {
			return err
		}
		var list struct {
			Messages []struct {
				ID   string
				Read bool
				To   []struct{ Address string }
			}
		}
		if err = json.Unmarshal(raw, &list); err != nil {
			return err
		}
		for _, msg := range list.Messages {
			if msg.Read {
				continue
			}
			matches := false
			for _, addr := range msg.To {
				if addr.Address == to {
					matches = true
				}
			}
			if !matches {
				continue
			}
			resp, err := client.Get("http://" + h.email.mp.apiAddr + "/api/v1/message/" + msg.ID)
			if err != nil {
				return err
			}
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			var full struct{ Text, HTML string }
			if err = json.Unmarshal(data, &full); err != nil {
				return err
			}
			if !strings.Contains(full.Text+full.HTML, summary) || !strings.Contains(full.Text+full.HTML, details) {
				continue
			}
			if os.Getenv("D08_T1_EVIDENCE") != "" {
				if err = os.WriteFile(filepath.Join(os.Getenv("D08_T1_EVIDENCE"), "sink-message-"+msg.ID+".json"), data, 0600); err != nil {
					return err
				}
			}
			body, _ := json.Marshal(map[string]any{"IDs": []string{msg.ID}, "Read": true})
			req, _ := http.NewRequest(http.MethodPut, "http://"+h.email.mp.apiAddr+"/api/v1/messages", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err = client.Do(req)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("sink mark status %d", resp.StatusCode)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("synthetic sink expectation timed out")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// OutboundIsolationDB opens the current synthetic smoke database; it does not
// discover or query any other database in the cluster.
func (h *Harness) OutboundIsolationDB() (*sql.DB, error) { return sql.Open("pgx", h.dbURL) }
