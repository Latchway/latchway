package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/spf13/cobra"
)

type adminSessionAdministratorCLI struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type adminSessionMetadataWireCLI struct {
	ID            string                       `json:"id"`
	Administrator adminSessionAdministratorCLI `json:"administrator"`
	CreatedAt     string                       `json:"created_at"`
	LastSeenAt    string                       `json:"last_seen_at"`
	ExpiresAt     string                       `json:"expires_at"`
	Status        string                       `json:"status"`
	Current       *bool                        `json:"current"`
}

type adminSessionPageInfoWireCLI struct {
	HasMore    *bool  `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type adminSessionPageWireCLI struct {
	Items *[]adminSessionMetadataWireCLI `json:"items"`
	Page  *adminSessionPageInfoWireCLI   `json:"page"`
}

type adminSessionMetadataCLI struct {
	ID            string                       `json:"id"`
	Administrator adminSessionAdministratorCLI `json:"administrator"`
	CreatedAt     string                       `json:"created_at"`
	LastSeenAt    string                       `json:"last_seen_at"`
	ExpiresAt     string                       `json:"expires_at"`
	Status        string                       `json:"status"`
	Current       bool                         `json:"current"`
}

type adminSessionPageCLI struct {
	Items []adminSessionMetadataCLI `json:"items"`
	Page  pageInfoCLI               `json:"page"`
}

type adminSessionRevocationCLI struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

func newAdminSessionsCommand(opts *options) *cobra.Command {
	values := &controlCommandOptions{}
	command := &cobra.Command{
		Use: "sessions", Short: "Inspect and revoke administrator sessions",
	}
	addControlTokenFlag(command, values)
	command.AddCommand(
		newAdminSessionsListCommand(opts, values),
		newAdminSessionRevokeCommand(opts, values),
	)
	return command
}

func newAdminSessionsListCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	var cursor string
	var pageSize int
	command := &cobra.Command{
		Use: "list", Short: "List redaction-safe administrator-session metadata", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if pageSize < 1 || pageSize > 200 || !validAdminSessionCursor(cursor, true) {
				return errors.New("administrator-session page size or cursor is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			query := url.Values{"page_size": []string{strconv.Itoa(pageSize)}}
			if cursor != "" {
				query.Set("cursor", cursor)
			}
			var wire adminSessionPageWireCLI
			if _, err := client.do(cmd.Context(), http.MethodGet, "/admin/v1/admin-sessions", query, nil, http.StatusOK, &wire); err != nil {
				return err
			}
			page, err := validateAdminSessionPage(wire, pageSize)
			if err != nil {
				return err
			}
			return printAdminSessions(opts, page)
		},
	}
	command.Flags().StringVar(&cursor, "cursor", "", "opaque next-page cursor")
	command.Flags().IntVar(&pageSize, "page-size", 50, "number of administrator sessions to return (1-200)")
	return command
}

func newAdminSessionRevokeCommand(opts *options, root *controlCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use: "revoke SESSION_ID", Short: "Immediately revoke one administrator session", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id.Validate(args[0], id.AdminSession) != nil {
				return errors.New("administrator session ID is invalid")
			}
			client, err := newControlAPIClient(opts, root.tokenEnvironment)
			if err != nil {
				return err
			}
			if _, err := client.do(
				cmd.Context(), http.MethodPost, "/admin/v1/admin-sessions/"+args[0]+"/revoke",
				nil, nil, http.StatusNoContent, nil,
			); err != nil {
				return err
			}
			return printAdminSessionRevocation(opts, adminSessionRevocationCLI{SessionID: args[0], Status: "revoked"})
		},
	}
}

func validateAdminSessionPage(wire adminSessionPageWireCLI, pageSize int) (adminSessionPageCLI, error) {
	if wire.Items == nil || wire.Page == nil || wire.Page.HasMore == nil || pageSize < 1 || pageSize > 200 {
		return adminSessionPageCLI{}, errors.New("admin API returned invalid administrator-session page metadata")
	}
	if len(*wire.Items) > pageSize || len(*wire.Items) > 200 {
		return adminSessionPageCLI{}, errors.New("admin API returned too many administrator sessions")
	}
	hasMore := *wire.Page.HasMore
	if hasMore {
		if len(*wire.Items) == 0 || !validAdminSessionCursor(wire.Page.NextCursor, false) {
			return adminSessionPageCLI{}, errors.New("admin API returned invalid administrator-session pagination metadata")
		}
	} else if wire.Page.NextCursor != "" {
		return adminSessionPageCLI{}, errors.New("admin API returned inconsistent administrator-session pagination metadata")
	}

	page := adminSessionPageCLI{
		Items: make([]adminSessionMetadataCLI, 0, len(*wire.Items)),
		Page:  pageInfoCLI{HasMore: hasMore, NextCursor: wire.Page.NextCursor},
	}
	seen := make(map[string]struct{}, len(*wire.Items))
	var previousCreated time.Time
	var previousID string
	for index, item := range *wire.Items {
		normalized, createdAt, err := validateAdminSessionMetadata(item)
		if err != nil {
			return adminSessionPageCLI{}, fmt.Errorf("admin API returned invalid administrator session at index %d: %w", index, err)
		}
		if _, duplicate := seen[normalized.ID]; duplicate {
			return adminSessionPageCLI{}, errors.New("admin API returned duplicate administrator sessions")
		}
		if index > 0 && (createdAt.Before(previousCreated) || (createdAt.Equal(previousCreated) && normalized.ID <= previousID)) {
			return adminSessionPageCLI{}, errors.New("admin API returned administrator sessions outside canonical order")
		}
		seen[normalized.ID] = struct{}{}
		previousCreated = createdAt
		previousID = normalized.ID
		page.Items = append(page.Items, normalized)
	}
	return page, nil
}

func validateAdminSessionMetadata(wire adminSessionMetadataWireCLI) (adminSessionMetadataCLI, time.Time, error) {
	if id.Validate(wire.ID, id.AdminSession) != nil {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("session ID is invalid")
	}
	if id.Validate(wire.Administrator.ID, id.AdminUser) != nil {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("administrator ID is invalid")
	}
	if !validAdminSessionEmail(wire.Administrator.Email) {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("administrator email is invalid")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("created timestamp is invalid")
	}
	lastSeenAt, err := time.Parse(time.RFC3339Nano, wire.LastSeenAt)
	if err != nil || lastSeenAt.IsZero() || lastSeenAt.Before(createdAt) {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("last-seen timestamp is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, wire.ExpiresAt)
	if err != nil || expiresAt.IsZero() || !expiresAt.After(createdAt) || expiresAt.Before(lastSeenAt) {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("expiration timestamp is invalid")
	}
	if wire.Status != "active" && wire.Status != "expired" && wire.Status != "revoked" {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("status is invalid")
	}
	if wire.Current == nil {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("current flag is missing")
	}
	if *wire.Current {
		return adminSessionMetadataCLI{}, time.Time{}, errors.New("current flag is invalid for bearer authentication")
	}
	return adminSessionMetadataCLI{
		ID: wire.ID, Administrator: wire.Administrator,
		CreatedAt: wire.CreatedAt, LastSeenAt: wire.LastSeenAt, ExpiresAt: wire.ExpiresAt,
		Status: wire.Status, Current: false,
	}, createdAt, nil
}

func validAdminSessionEmail(value string) bool {
	if value == "" || len(value) > 320 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || hasUnsafeAdminSessionText(value) {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value
}

func validAdminSessionCursor(value string, emptyAllowed bool) bool {
	if value == "" {
		return emptyAllowed
	}
	if len(value) > 2048 || !utf8.ValidString(value) || hasUnsafeAdminSessionText(value) {
		return false
	}
	for index := range value {
		character := value[index]
		if (character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func hasUnsafeAdminSessionText(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func printAdminSessions(opts *options, page adminSessionPageCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, session := range page.Items {
		rows = append(rows, []string{
			session.ID, session.Administrator.ID, session.Administrator.Email,
			formatControlTime(session.CreatedAt), formatControlTime(session.LastSeenAt),
			formatControlTime(session.ExpiresAt), session.Status, boolLabel(session.Current),
		})
	}
	if err := printControlTable(
		opts,
		[]string{"SESSION", "ADMINISTRATOR", "EMAIL", "CREATED", "LAST SEEN", "EXPIRES", "STATUS", "CURRENT"},
		rows,
	); err != nil {
		return err
	}
	if page.Page.HasMore {
		_, err := fmt.Fprintf(opts.stdout, "next cursor: %s\n", page.Page.NextCursor)
		return err
	}
	return nil
}

func printAdminSessionRevocation(opts *options, result adminSessionRevocationCLI) error {
	if opts.output == "json" {
		return printControlJSON(opts, result)
	}
	return printControlTable(opts, []string{"SESSION", "STATUS"}, [][]string{{result.SessionID, result.Status}})
}
