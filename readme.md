# Simple REST API Using Actix Web and Diesel with JWT Authentication

## To setup the project:

```console
cargo install diesel_cli
```

## Env Variables:

```console
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
APP_TOKEN=your_secret_token
AUTH_TOKEN=secret_token
```

## To setup diesel cli:

```console
diesel setup
```

## To create a new migration:

```console
diesel migration generate create_users_table
```

## To run the migrations:

```console
diesel migration run
```

## To rollback the migrations:

```console
diesel migration rollback
```

## To print the schema:

```console
diesel print-schema
```

## To run the project:

### Development:

```console
cargo watch -q -c -w src/ -x run
```

### Production:

```console
cargo run
```

## To run the tests:

```console
cargo test
```

## To run the tests:

```console
cargo run --bin server
```
