package smoke

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

func TestListAlerts(t *testing.T) {
	t.Parallel()

	sql := `
	insert into escalation_policies (id, name, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', {{smokeOrganizationID}});
`
	for i := 0; i < 160; i++ {
		name := "s" + strconv.Itoa(i)
		sql += `
			insert into services (id, name, escalation_policy_id, organization_id) values ({{uuid "` + name + `"}}, '` + name + `', {{uuid "eid"}}, {{smokeOrganizationID}});
			insert into alerts (service_id, summary, dedup_key) values ({{uuid "` + name + `"}}, 'hi', 'auto:1:smoke:listalerts:` + name + `');
		`
	}

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	resp := h.GraphQLQuery2(`
		query {
			alerts {
				nodes {
					alertID
					service {
						id
						name
					}
				}
			}
		}
	`)
	for _, err := range resp.Errors {
		t.Error("fetch alerts:", err)
	}

	var res struct {
		Alerts struct {
			Nodes []struct {
				ID      int `json:"alertID"`
				Service struct {
					ID   string
					Name string
				}
			}
		}
	}

	err := json.Unmarshal(resp.Data, &res)
	if err != nil {
		t.Fatal("failed to parse response:", err)
	}

	if len(res.Alerts.Nodes) == 0 {
		t.Error("got 0 alerts; expected at least 1")
	}
	for _, a := range res.Alerts.Nodes {
		name := "s" + strconv.Itoa(a.ID-1)
		if a.Service.Name != name {
			t.Errorf("Alert[%d].Service.Name = %s; want %s", a.ID, a.Service.Name, name)
		}
	}
}
