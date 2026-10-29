package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jmoiron/sqlx"

	"backend/internal/domain"
	errs "backend/internal/errors"
	"backend/internal/service"
)

var _ service.ThreatRepository = (*ThreatRepository)(nil)

const threatColumns = `md5, name, type, platform, severity, status, sha256,
 file_size, description, tags, first_seen, last_seen, created_at, updated_at`

const createThreat = `INSERT INTO threats (` + threatColumns + `)
 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
 RETURNING ` + threatColumns

const updateThreat = `UPDATE threats SET name=$2, type=$3, platform=$4,
 severity=$5, status=$6, sha256=$7, file_size=$8, description=$9, tags=$10,
 first_seen=$11, last_seen=$12, updated_at=$13
 WHERE md5=$1 RETURNING ` + threatColumns

type ThreatRepository struct{ db *sqlx.DB }

func NewThreatRepository(db *sqlx.DB) *ThreatRepository { return &ThreatRepository{db: db} }

func (r *ThreatRepository) Create(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	args := threatArgs(threat)
	args = append(args, threat.CreatedAt, threat.UpdatedAt)

	saved, err := scanThreat(r.db.QueryRowxContext(ctx, createThreat, args...))
	if err != nil {
		return domain.Threat{}, mapError("insert threat", err)
	}

	return saved, nil
}

func (r *ThreatRepository) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	saved, err := scanThreat(r.db.QueryRowxContext(ctx, `SELECT `+threatColumns+` FROM threats WHERE md5=$1`, md5))
	if err != nil {
		return domain.Threat{}, mapError("select threat", err)
	}

	return saved, nil
}

func (r *ThreatRepository) Update(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	// CreatedAt не участвует в UPDATE: исходное время создания возвращается самой БД.
	args := append(threatArgs(threat), threat.UpdatedAt)

	saved, err := scanThreat(r.db.QueryRowxContext(ctx, updateThreat, args...))
	if err != nil {
		return domain.Threat{}, mapError("update threat", err)
	}

	return saved, nil
}

func threatArgs(threat domain.Threat) []any {
	tags := threat.Tags
	if tags == nil {
		tags = []string{}
	}

	return []any{threat.MD5, threat.Name, threat.Type, threat.Platform, threat.Severity, threat.Status,
		threat.SHA256, threat.FileSize, threat.Description, tags, threat.FirstSeen, threat.LastSeen}
}

func scanThreat(row *sqlx.Row) (domain.Threat, error) {
	var threat domain.Threat
	// database/sql не умеет сканировать TEXT[] в []string без сканера драйвера.
	err := row.Scan(&threat.MD5, &threat.Name, &threat.Type, &threat.Platform, &threat.Severity, &threat.Status,
		&threat.SHA256, &threat.FileSize, &threat.Description, pgtype.NewMap().SQLScanner(&threat.Tags),
		&threat.FirstSeen, &threat.LastSeen, &threat.CreatedAt, &threat.UpdatedAt)
	if err != nil {
		return domain.Threat{}, err
	}

	threat.CreatedAt = threat.CreatedAt.UTC()

	threat.UpdatedAt = threat.UpdatedAt.UTC()
	if threat.FirstSeen != nil {
		v := threat.FirstSeen.UTC()
		threat.FirstSeen = &v
	}

	if threat.LastSeen != nil {
		v := threat.LastSeen.UTC()
		threat.LastSeen = &v
	}

	return threat, nil
}

func mapError(operation string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", operation, errs.ErrNotFound)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "threats_pkey" {
		return fmt.Errorf("%s: %w", operation, errs.ErrAlreadyExists)
	}

	return fmt.Errorf("%s: %w", operation, err)
}
