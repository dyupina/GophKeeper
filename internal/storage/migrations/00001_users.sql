-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    uid      TEXT UNIQUE,
    login    TEXT UNIQUE NOT NULL,
    password BYTEA NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
