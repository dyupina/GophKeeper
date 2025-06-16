-- +goose Up
-- +goose StatementBegin
CREATE TYPE data_type_enum AS ENUM ('login_password', 'text', 'binary', 'bank_card');
CREATE TABLE private_data (
    id         INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    uid        TEXT NOT NULL REFERENCES users(uid),
    data_key   TEXT NOT NULL, -- Ключ для идентификации данных. Например, имя файла ("email_password.txt", "passwords", "notes")
    data_value TEXT NOT NULL,
    data_type  data_type_enum NOT NULL,
    metadata   JSONB DEFAULT '{}'::JSONB, -- Метаданные в формате JSON
    salt       BYTEA NOT NULL,
    UNIQUE (uid, data_key)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS private_data;
DROP TYPE data_type_enum;
-- +goose StatementEnd
