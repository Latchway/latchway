package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
)

const maximumSimulationScenarios = 200

var errScenarioNameTaken = errors.New("simulation scenario name taken")

// simulationScenarioDocument is one saved simulator input. Input is a
// route-simulation request without application or environment, validated
// exactly as a simulation would be.
type simulationScenarioDocument struct {
	ID            string                 `json:"id"`
	ApplicationID string                 `json:"application_id"`
	Name          string                 `json:"name"`
	Input         routeSimulationRequest `json:"input"`
	Version       int64                  `json:"version"`
	CreatedBy     string                 `json:"created_by"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedBy     string                 `json:"updated_by"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

type simulationScenarioRequest struct {
	Name    string                 `json:"name"`
	Input   routeSimulationRequest `json:"input"`
	Version int64                  `json:"version,omitempty"`
}

func validScenarioName(name string) bool {
	trimmed := strings.TrimSpace(name)
	return trimmed == name && name != "" && utf8.ValidString(name) && utf8.RuneCountInString(name) <= 100 &&
		!strings.ContainsAny(name, "\r\n\t\x00")
}

// scenarioInput validates a scenario's input like a simulation request and
// returns its canonical stored form.
func scenarioInput(input routeSimulationRequest) ([]byte, bool) {
	if input.ApplicationID != "" || input.EnvironmentID != "" ||
		!operationalIdentifierPattern.MatchString(input.Feature) || !validRouteSimulationRequest(&input) {
		return nil, false
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 16_384 {
		return nil, false
	}
	return encoded, true
}

func (store *operationalStore) canSimulateIn(ctx context.Context, principal adminauth.Principal, applicationID string) error {
	if id.Validate(applicationID, id.Application) != nil {
		return errOperationalInvalid
	}
	if !principal.AllowsSomewhere(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return errOperationalForbidden
	}
	var exists bool
	if err := store.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND application_id = $2)
	`, principal.OrganizationID, applicationID).Scan(&exists); err != nil {
		return fmt.Errorf("check simulation scenario application: %w", err)
	}
	if !exists {
		return errOperationalNotFound
	}
	if !principal.AllowsIn(adminauth.ActivateConfiguration, applicationID, adminauth.AuthorizationContext{}) {
		return errOperationalForbidden
	}
	return nil
}

const scenarioColumns = `
	simulation_scenario_id, application_id, name, input, version,
	created_by_admin_user_id, created_at, updated_by_admin_user_id, updated_at`

func scanScenario(row rowScanner) (simulationScenarioDocument, error) {
	var scenario simulationScenarioDocument
	var input []byte
	if err := row.Scan(&scenario.ID, &scenario.ApplicationID, &scenario.Name, &input, &scenario.Version,
		&scenario.CreatedBy, &scenario.CreatedAt, &scenario.UpdatedBy, &scenario.UpdatedAt); err != nil {
		return simulationScenarioDocument{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(input)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scenario.Input); err != nil {
		return simulationScenarioDocument{}, errOperationalCorrupt
	}
	scenario.CreatedAt, scenario.UpdatedAt = scenario.CreatedAt.UTC(), scenario.UpdatedAt.UTC()
	return scenario, nil
}

func (store *operationalStore) listSimulationScenarios(ctx context.Context, principal adminauth.Principal, applicationID string) ([]simulationScenarioDocument, error) {
	if err := store.canSimulateIn(ctx, principal, applicationID); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `SELECT `+scenarioColumns+`
		FROM simulation_scenarios
		WHERE organization_id = $1 AND application_id = $2
		ORDER BY updated_at DESC, simulation_scenario_id DESC
		LIMIT $3
	`, principal.OrganizationID, applicationID, maximumSimulationScenarios)
	if err != nil {
		return nil, fmt.Errorf("list simulation scenarios: %w", err)
	}
	defer rows.Close()
	items := make([]simulationScenarioDocument, 0)
	for rows.Next() {
		scenario, err := scanScenario(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, scenario)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate simulation scenarios: %w", err)
	}
	return items, nil
}

func (store *operationalStore) createSimulationScenario(ctx context.Context, principal adminauth.Principal, applicationID string, request simulationScenarioRequest, requestID string) (simulationScenarioDocument, error) {
	input, ok := scenarioInput(request.Input)
	if !ok || !validScenarioName(request.Name) || request.Version != 0 {
		return simulationScenarioDocument{}, errOperationalInvalid
	}
	if err := store.canSimulateIn(ctx, principal, applicationID); err != nil {
		return simulationScenarioDocument{}, err
	}
	scenarioID, err := store.newID(id.SimulationScenario)
	if err != nil {
		return simulationScenarioDocument{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return simulationScenarioDocument{}, fmt.Errorf("begin simulation scenario creation: %w", err)
	}
	defer rollbackOperational(tx)
	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM simulation_scenarios WHERE organization_id = $1 AND application_id = $2
	`, principal.OrganizationID, applicationID).Scan(&count); err != nil {
		return simulationScenarioDocument{}, fmt.Errorf("count simulation scenarios: %w", err)
	}
	if count >= maximumSimulationScenarios {
		return simulationScenarioDocument{}, errOperationalConflict
	}
	scenario, err := scanScenario(tx.QueryRow(ctx, `
		INSERT INTO simulation_scenarios (
			simulation_scenario_id, organization_id, application_id, name, input,
			created_by_admin_user_id, created_at, updated_by_admin_user_id, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, statement_timestamp(), $6, statement_timestamp())
		RETURNING `+scenarioColumns,
		scenarioID, principal.OrganizationID, applicationID, request.Name, input, principal.AdminUserID))
	if err != nil {
		return simulationScenarioDocument{}, mapScenarioWrite(err)
	}
	changes, err := scenarioAuditChanges()
	if err != nil {
		return simulationScenarioDocument{}, err
	}
	if err := store.audit(ctx, tx, principal, "", "admin.simulation_scenario_create", "simulation_scenario",
		scenarioID, requestID, scenario.CreatedAt, changes); err != nil {
		return simulationScenarioDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return simulationScenarioDocument{}, fmt.Errorf("commit simulation scenario creation: %w", err)
	}
	return scenario, nil
}

func (store *operationalStore) replaceSimulationScenario(ctx context.Context, principal adminauth.Principal, scenarioID string, request simulationScenarioRequest, requestID string) (simulationScenarioDocument, error) {
	input, ok := scenarioInput(request.Input)
	if !ok || !validScenarioName(request.Name) || request.Version < 1 || id.Validate(scenarioID, id.SimulationScenario) != nil {
		return simulationScenarioDocument{}, errOperationalInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return simulationScenarioDocument{}, fmt.Errorf("begin simulation scenario replacement: %w", err)
	}
	defer rollbackOperational(tx)
	current, err := store.lockScenario(ctx, tx, principal, scenarioID)
	if err != nil {
		return simulationScenarioDocument{}, err
	}
	if current.Version != request.Version {
		return simulationScenarioDocument{}, errOperationalConflict
	}
	scenario, err := scanScenario(tx.QueryRow(ctx, `
		UPDATE simulation_scenarios
		SET name = $3, input = $4, version = version + 1,
		    updated_by_admin_user_id = $5, updated_at = greatest(statement_timestamp(), created_at)
		WHERE organization_id = $1 AND simulation_scenario_id = $2
		RETURNING `+scenarioColumns,
		principal.OrganizationID, scenarioID, request.Name, input, principal.AdminUserID))
	if err != nil {
		return simulationScenarioDocument{}, mapScenarioWrite(err)
	}
	changes, err := scenarioAuditChanges()
	if err != nil {
		return simulationScenarioDocument{}, err
	}
	if err := store.audit(ctx, tx, principal, "", "admin.simulation_scenario_update", "simulation_scenario",
		scenarioID, requestID, scenario.UpdatedAt, changes); err != nil {
		return simulationScenarioDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return simulationScenarioDocument{}, fmt.Errorf("commit simulation scenario replacement: %w", err)
	}
	return scenario, nil
}

func (store *operationalStore) deleteSimulationScenario(ctx context.Context, principal adminauth.Principal, scenarioID string, version int64, requestID string) error {
	if id.Validate(scenarioID, id.SimulationScenario) != nil || version < 1 {
		return errOperationalInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin simulation scenario deletion: %w", err)
	}
	defer rollbackOperational(tx)
	current, err := store.lockScenario(ctx, tx, principal, scenarioID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return errOperationalConflict
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM simulation_scenarios WHERE organization_id = $1 AND simulation_scenario_id = $2
	`, principal.OrganizationID, scenarioID); err != nil {
		return fmt.Errorf("delete simulation scenario: %w", err)
	}
	removed, err := adminauth.NewPublicAuditChange("scenario", adminauth.AuditRemove)
	if err != nil {
		return err
	}
	if err := store.audit(ctx, tx, principal, "", "admin.simulation_scenario_delete", "simulation_scenario",
		scenarioID, requestID, time.Now(), []adminauth.AuditChange{removed}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit simulation scenario deletion: %w", err)
	}
	return nil
}

func (store *operationalStore) lockScenario(ctx context.Context, tx pgx.Tx, principal adminauth.Principal, scenarioID string) (simulationScenarioDocument, error) {
	if !principal.AllowsSomewhere(adminauth.ActivateConfiguration, adminauth.AuthorizationContext{}) {
		return simulationScenarioDocument{}, errOperationalForbidden
	}
	scenario, err := scanScenario(tx.QueryRow(ctx, `SELECT `+scenarioColumns+`
		FROM simulation_scenarios
		WHERE organization_id = $1 AND simulation_scenario_id = $2
		FOR UPDATE
	`, principal.OrganizationID, scenarioID))
	if errors.Is(err, pgx.ErrNoRows) {
		return simulationScenarioDocument{}, errOperationalNotFound
	}
	if err != nil {
		return simulationScenarioDocument{}, err
	}
	if !principal.AllowsIn(adminauth.ActivateConfiguration, scenario.ApplicationID, adminauth.AuthorizationContext{}) {
		return simulationScenarioDocument{}, errOperationalForbidden
	}
	return scenario, nil
}

// scenarioAuditChanges marks the saved input as sensitive: it can hold test
// claim values, which never enter the audit log.
func scenarioAuditChanges() ([]adminauth.AuditChange, error) {
	name, err := adminauth.NewPublicAuditChange("name", adminauth.AuditSet)
	if err != nil {
		return nil, err
	}
	input, err := adminauth.NewSensitiveAuditChange("input", adminauth.AuditSet)
	if err != nil {
		return nil, err
	}
	return []adminauth.AuditChange{name, input}, nil
}

func mapScenarioWrite(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "23505" {
		return errScenarioNameTaken
	}
	return fmt.Errorf("write simulation scenario: %w", err)
}

func (api *API) handleScenarioError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errScenarioNameTaken) {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "Another scenario in this application already has that name."})
		return
	}
	if errors.Is(err, errOperationalConflict) {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The scenario changed since it was loaded, or the application already has 200 scenarios."})
		return
	}
	api.handleOperationalError(w, r, err, "")
}

func (api *API) simulationScenarios(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The simulation-scenario query is invalid."))
		return
	}
	items, err := api.operations.listSimulationScenarios(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "applicationID"))
	if err != nil {
		api.handleScenarioError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (api *API) createSimulationScenario(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[simulationScenarioRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The simulation scenario is invalid."))
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	scenario, err := api.operations.createSimulationScenario(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "applicationID"), request, requestID)
	if err != nil {
		api.handleScenarioError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, scenario)
}

func (api *API) replaceSimulationScenario(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[simulationScenarioRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The simulation scenario is invalid."))
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	scenario, err := api.operations.replaceSimulationScenario(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "scenarioID"), request, requestID)
	if err != nil {
		api.handleScenarioError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scenario)
}

func (api *API) deleteSimulationScenario(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "version") {
		api.writeProblem(w, r, invalidRequest("The simulation-scenario query is invalid."))
		return
	}
	raw, ok := requiredQueryValue(r, "version")
	version, err := strconv.ParseInt(raw, 10, 64)
	if !ok || err != nil {
		api.writeProblem(w, r, invalidRequest("Deleting a scenario needs the version that was loaded."))
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.operations.deleteSimulationScenario(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "scenarioID"), version, requestID); err != nil {
		api.handleScenarioError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
