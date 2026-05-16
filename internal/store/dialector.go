package store

import (
	"database/sql"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/migrator"
	"gorm.io/gorm/schema"
)

type d1Dialector struct {
	sqlDB *sql.DB
}

func newDialector(sqlDB *sql.DB) gorm.Dialector {
	return &d1Dialector{sqlDB: sqlDB}
}

func (d *d1Dialector) Name() string { return "sqlite" }

func (d *d1Dialector) Initialize(db *gorm.DB) error {
	db.ConnPool = d.sqlDB
	callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
		LastInsertIDReversed: true,
	})
	return nil
}

func (d *d1Dialector) Migrator(db *gorm.DB) gorm.Migrator {
	return &migrator.Migrator{
		Config: migrator.Config{
			DB:        db,
			Dialector: d,
		},
	}
}

func (d *d1Dialector) DataTypeOf(field *schema.Field) string {
	switch field.DataType {
	case schema.Bool:
		return "numeric"
	case schema.Int, schema.Uint:
		return "integer"
	case schema.Float:
		return "real"
	case schema.String:
		return "text"
	case schema.Time:
		return "datetime"
	case schema.Bytes:
		return "blob"
	}
	return string(field.DataType)
}

func (d *d1Dialector) DefaultValueOf(_ *schema.Field) clause.Expression {
	return clause.Expr{SQL: "DEFAULT"}
}

func (d *d1Dialector) BindVarTo(writer clause.Writer, _ *gorm.Statement, _ interface{}) {
	writer.WriteByte('?')
}

func (d *d1Dialector) QuoteTo(writer clause.Writer, str string) {
	if str == "" || str == "*" {
		writer.WriteString(str)
		return
	}
	if idx := strings.Index(str, "."); idx >= 0 {
		d.QuoteTo(writer, str[:idx])
		writer.WriteByte('.')
		d.QuoteTo(writer, str[idx+1:])
		return
	}
	writer.WriteByte('`')
	writer.WriteString(strings.ReplaceAll(str, "`", "``"))
	writer.WriteByte('`')
}

func (d *d1Dialector) Explain(sql string, vars ...interface{}) string {
	return logger.ExplainSQL(sql, nil, `"`, vars...)
}
