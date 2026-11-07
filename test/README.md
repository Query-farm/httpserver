# Testing this extension

The `sql` directory holds [SQLLogicTests](https://duckdb.org/dev/sqllogictest/intro.html), run with:

```bash
make test
```

Tests that send real HTTP requests to the server (`httpserver.test`, `httpserver_auth.test`,
`httpserver_requests.test`) read from it with `httpfs`; they are skipped when `httpfs` can't be loaded.

The `python` directory holds pytest tests that drive the server with plain HTTP requests (formats, auth,
browser origin checks, port conflicts between two databases):

```bash
pip install duckdb pytest
HTTPSERVER_EXTENSION_BINARY_PATH=build/release/extension/httpserver/httpserver.duckdb_extension \
  pytest test/python
```

The `duckdb` Python package must be the same DuckDB version the extension was built for.
