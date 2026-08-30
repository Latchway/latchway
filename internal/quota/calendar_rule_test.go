package quota

import "testing"

func TestPrepareRulesCanonicalizesCalendarTimezoneWithoutChangingUTCIdentity(t *testing.T) {
	t.Parallel()
	base := Rule{
		Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1w", Maximum: 10, Hard: true,
	}
	values := map[string]string{"user": "user_123"}
	omitted, err := prepareRules([]Rule{base}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	explicitRule := base
	explicitRule.Timezone = "UTC"
	explicit, err := prepareRules([]Rule{explicitRule}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	ianaRule := base
	ianaRule.Timezone = "America/New_York"
	iana, err := prepareRules([]Rule{ianaRule}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	if omitted[0].Timezone != "UTC" || explicit[0].Timezone != "UTC" ||
		omitted[0].ruleKey != explicit[0].ruleKey {
		t.Fatalf("UTC rule identity changed: omitted=%+v explicit=%+v", omitted[0], explicit[0])
	}
	if iana[0].Timezone != "America/New_York" || iana[0].ruleKey == omitted[0].ruleKey {
		t.Fatalf("IANA timezone did not isolate rule identity: UTC=%+v IANA=%+v", omitted[0], iana[0])
	}
	if _, err := prepareRules([]Rule{base, explicitRule}, values, reserveRulePreparation); err == nil {
		t.Fatal("omitted and explicit UTC duplicate identities were accepted")
	}
}

func TestPrepareRulesRejectsInvalidOrNonCalendarTimezone(t *testing.T) {
	t.Parallel()
	calendar := Rule{
		Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1w", Timezone: "Not/A_Real_Zone",
		Maximum: 10, Hard: true,
	}
	if _, err := prepareRules([]Rule{calendar}, map[string]string{"user": "user_123"}, reserveRulePreparation); err == nil {
		t.Fatal("invalid calendar timezone was accepted")
	}
	tokenBucket := Rule{
		Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
		Scope: []string{"user"}, Timezone: "UTC", Capacity: 10,
		RefillNumerator: 1, RefillDenominator: 1, Hard: true,
	}
	if _, err := prepareRules([]Rule{tokenBucket}, map[string]string{"user": "user_123"}, reserveRulePreparation); err == nil {
		t.Fatal("timezone on a non-calendar rule was accepted")
	}
}
