package postgres

import "github.com/target/goalert/util/sqlutil"

// Validate ordinary Key roots without projecting credential IDs or config JSON.
// A Universal Key without its normal config is not a supported success fixture.
// Historical non-FK edges must resolve to a real Alert/Service in the Key's org,
// including for a global System collector. Broken joins cannot become Complete.
func (c *collector) validateIntegrationKeys(ids []string) error {
	var invalid bool
	err := c.queryRow(`SELECT EXISTS(SELECT FROM public.integration_keys k
 LEFT JOIN public.services s ON s.id=k.service_id
 LEFT JOIN public.organizations o ON o.id=s.organization_id
 LEFT JOIN public.normal_organizations n ON n.organization_id=o.id AND n.organization_classification=o.classification
 WHERE k.audit_resource_id=ANY($1::uuid[]) AND (
 k.id='00000000-0000-0000-0000-000000000000'::uuid OR k.id=k.audit_resource_id
 OR k.audit_resource_id='00000000-0000-0000-0000-000000000000'::uuid
 OR s.id IS NULL OR o.id IS NULL
 OR NOT (o.classification='NORMAL' AND n.organization_id IS NOT NULL
 OR o.classification='DEFAULT' AND o.id='296e2656-7221-53fe-bd0a-832d24ccfd03'::uuid)
 OR k.type::text NOT IN ('email','generic','grafana','prometheusAlertmanager','site24x7')
 OR EXISTS(SELECT FROM public.uik_config cfg WHERE cfg.id=k.id)
 OR EXISTS(SELECT FROM public.alert_logs l
 LEFT JOIN public.alerts a ON a.id=l.alert_id
 LEFT JOIN public.services h ON h.id=a.service_id
 WHERE l.sub_integration_key_id=k.id AND (a.id IS NULL OR h.id IS NULL OR h.organization_id IS DISTINCT FROM s.organization_id))))`, sqlutil.StringArray(ids)).Scan(&invalid)
	if err != nil {
		return err
	}
	if invalid {
		return errUnsupported
	}
	return nil
}
