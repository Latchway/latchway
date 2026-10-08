package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/latchway/latchway/internal/id"
)

type healthSampleCLI struct {
	SampledAt     string   `json:"sampled_at"`
	OverallState  string   `json:"overall_state"`
	FailedChecks  []string `json:"failed_checks"`
	WarningChecks []string `json:"warning_checks"`
}

type healthHistoryCLI struct {
	Start           string            `json:"start"`
	End             string            `json:"end"`
	IntervalSeconds int64             `json:"interval_seconds"`
	Samples         []healthSampleCLI `json:"samples"`
}

type connectionFailureCLI struct {
	Code  string      `json:"code"`
	Count json.Number `json:"count"`
}

type connectionHealthCLI struct {
	Upstream     string                 `json:"upstream"`
	Attempts     json.Number            `json:"attempts"`
	Succeeded    json.Number            `json:"succeeded"`
	Failed       json.Number            `json:"failed"`
	Canceled     json.Number            `json:"canceled"`
	RateLimited  json.Number            `json:"rate_limited"`
	ServerErrors json.Number            `json:"server_errors"`
	FellBack     json.Number            `json:"fell_back"`
	Failures     []connectionFailureCLI `json:"failures"`
	FirstByte    usageDistributionCLI   `json:"first_byte"`
	Duration     usageDistributionCLI   `json:"duration"`
	Usage        usageValuesCLI         `json:"usage"`
}

type connectionPointCLI struct {
	Upstream  string      `json:"upstream"`
	Timestamp string      `json:"timestamp"`
	Attempts  json.Number `json:"attempts"`
	Failed    json.Number `json:"failed"`
}

type connectionHealthDocumentCLI struct {
	EnvironmentID string                `json:"environment_id"`
	Start         string                `json:"start"`
	End           string                `json:"end"`
	Interval      string                `json:"interval,omitempty"`
	Connections   []connectionHealthCLI `json:"connections"`
	Truncated     bool                  `json:"truncated"`
	Series        []connectionPointCLI  `json:"series,omitempty"`
}

type selfTestRunPageCLI struct {
	Items []selfTestRunCLI `json:"items"`
	Page  pageInfoCLI      `json:"page"`
}

var selfTestRunStates = []string{"queued", "running", "passed", "failed", "canceled"}

func newStatusHistoryCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var start, end string
	command := &cobra.Command{
		Use: "history", Short: "Show the server self-check sampled every five minutes (at most 7 days)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			query, err := boundedRangeQuery(start, end, 7*24*time.Hour, "health history")
			if err != nil {
				return err
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var history healthHistoryCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/system/health-history", query, nil, http.StatusOK, &history); err != nil {
				return err
			}
			if opts.output == "json" {
				return printControlJSON(opts, history)
			}
			rows := make([][]string, 0, len(history.Samples))
			healthy := 0
			for _, sample := range history.Samples {
				if sample.OverallState == "healthy" {
					healthy++
				}
				rows = append(rows, []string{formatControlTime(sample.SampledAt), sample.OverallState, strings.Join(sample.FailedChecks, ","), strings.Join(sample.WarningChecks, ",")})
			}
			if len(history.Samples) == 0 {
				_, err := fmt.Fprintln(opts.stdout, "no samples: a worker records one every five minutes")
				return err
			}
			if _, err := fmt.Fprintf(opts.stdout, "healthy samples: %d of %d\n", healthy, len(history.Samples)); err != nil {
				return err
			}
			return printControlTable(opts, []string{"SAMPLED AT", "STATE", "FAILED CHECKS", "WARNING CHECKS"}, rows)
		},
	}
	command.Flags().StringVar(&start, "start", "", "inclusive RFC 3339 start (defaults to 24 hours before end)")
	command.Flags().StringVar(&end, "end", "", "exclusive RFC 3339 end (defaults to now)")
	return command
}

func newUsageConnectionsCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, start, end, interval string
	command := &cobra.Command{
		Use: "connections", Short: "Summarize upstream attempts per AI connection from recorded requests", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil || (interval != "" && interval != "hour" && interval != "day") {
				return errors.New("connection environment or interval is invalid")
			}
			maximum := 90 * 24 * time.Hour
			if interval == "hour" {
				maximum = 14 * 24 * time.Hour
			}
			query, err := boundedRangeQuery(start, end, maximum, "connection health")
			if err != nil {
				return err
			}
			query.Set("environment_id", environmentID)
			if interval != "" {
				query.Set("interval", interval)
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var document connectionHealthDocumentCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/usage/connections", query, nil, http.StatusOK, &document); err != nil {
				return err
			}
			if document.EnvironmentID != environmentID {
				return errors.New("admin API returned connection health for another environment")
			}
			if opts.output == "json" {
				return printControlJSON(opts, document)
			}
			rows := make([][]string, 0, len(document.Connections))
			for _, item := range document.Connections {
				failure := ""
				if len(item.Failures) > 0 {
					failure = item.Failures[0].Code + "=" + item.Failures[0].Count.String()
				}
				rows = append(rows, []string{
					item.Upstream, item.Attempts.String(), item.Succeeded.String(), item.Failed.String(), item.Canceled.String(),
					item.RateLimited.String(), item.ServerErrors.String(), item.FellBack.String(),
					usageDistributionText(item.FirstByte), failure, item.Usage.CostNanoUSD.String(),
				})
			}
			if err := printControlTable(opts, []string{"CONNECTION", "ATTEMPTS", "SUCCEEDED", "FAILED", "CANCELED", "429", "5XX", "FELL BACK", "FIRST BYTE P50/P95/P99 MS", "TOP FAILURE", "COST NANO-USD"}, rows); err != nil {
				return err
			}
			if len(document.Series) > 0 {
				points := make([][]string, 0, len(document.Series))
				for _, point := range document.Series {
					points = append(points, []string{formatControlTime(point.Timestamp), point.Upstream, point.Attempts.String(), point.Failed.String()})
				}
				if err := printControlTable(opts, []string{"BUCKET", "CONNECTION", "ATTEMPTS", "FAILED"}, points); err != nil {
					return err
				}
			}
			if document.Truncated {
				_, err := fmt.Fprintln(opts.stdout, "truncated: only the 200 busiest connections are listed")
				return err
			}
			return nil
		},
	}
	usageRangeFlags(command, &environmentID, &start, &end)
	command.Flags().StringVar(&interval, "interval", "", "add a UTC series: hour (at most 14 days) or day (at most 90 days)")
	return command
}

func newVerifyRunsCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var environmentID, scheduleID, state, cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "runs", Short: "List recent self-test runs in an environment, newest first", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id.Validate(environmentID, id.Environment) != nil {
				return errors.New("self-test environment is invalid")
			}
			if (scheduleID != "" && id.Validate(scheduleID, id.SelfTestSchedule) != nil) || (state != "" && !slices.Contains(selfTestRunStates, state)) {
				return errors.New("self-test schedule or state filter is invalid")
			}
			query, err := pageQuery(environmentID, cursor, pageSize)
			if err != nil {
				return err
			}
			if scheduleID != "" {
				query.Set("schedule_id", scheduleID)
			}
			if state != "" {
				query.Set("state", state)
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			var page selfTestRunPageCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/self-tests", query, nil, http.StatusOK, &page); err != nil {
				return err
			}
			for _, run := range page.Items {
				if run.EnvironmentID != environmentID {
					return errors.New("admin API returned a self-test run for another environment")
				}
			}
			if opts.output == "json" {
				return printControlJSON(opts, page)
			}
			rows := make([][]string, 0, len(page.Items))
			for _, run := range page.Items {
				rows = append(rows, []string{run.ID, run.Kind, run.State, run.ScheduleID, formatControlTime(run.CreatedAt), formatControlTime(run.CompletedAt)})
			}
			if err := printControlTable(opts, []string{"SELF-TEST", "KIND", "STATE", "SCHEDULE", "CREATED", "COMPLETED"}, rows); err != nil {
				return err
			}
			if page.Page.HasMore {
				_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
				return err
			}
			return nil
		},
	}
	command.Flags().StringVar(&environmentID, "environment", "", "target environment ID")
	command.Flags().StringVar(&scheduleID, "schedule", "", "only runs started by this schedule")
	command.Flags().StringVar(&state, "state", "", "only runs in this state: "+strings.Join(selfTestRunStates, ", "))
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of runs to return (1-200)")
	_ = command.MarkFlagRequired("environment")
	return command
}

// boundedRangeQuery resolves --start/--end like the usage commands (24 hours
// ending now by default) and refuses ranges longer than maximum.
func boundedRangeQuery(startRaw, endRaw string, maximum time.Duration, what string) (url.Values, error) {
	end := time.Now().UTC()
	if endRaw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, endRaw)
		if err != nil {
			return nil, errors.New("--end must be an RFC 3339 instant")
		}
		end = parsed.UTC()
	}
	start := end.Add(-24 * time.Hour)
	if startRaw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, startRaw)
		if err != nil {
			return nil, errors.New("--start must be an RFC 3339 instant")
		}
		start = parsed.UTC()
	}
	if !start.Before(end) || end.Sub(start) > maximum {
		return nil, fmt.Errorf("%s range must be positive and no longer than %s days", what, strconv.Itoa(int(maximum/(24*time.Hour))))
	}
	return url.Values{"start": []string{start.Format(time.RFC3339Nano)}, "end": []string{end.Format(time.RFC3339Nano)}}, nil
}
