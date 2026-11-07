import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

import duckdb
import pytest


def connect():
    extension_binary = os.getenv('HTTPSERVER_EXTENSION_BINARY_PATH')
    if not extension_binary:
        raise Exception('Please make sure the `HTTPSERVER_EXTENSION_BINARY_PATH` is set to run the python tests')
    conn = duckdb.connect('', config={'allow_unsigned_extensions': 'true'})
    conn.execute(f"LOAD '{extension_binary}'")
    return conn


def start(conn, host='127.0.0.1', port=0, auth=''):
    message = conn.execute("SELECT httpserve_start(?, ?, ?)", [host, port, auth]).fetchone()[0]
    return int(message.rsplit(':', 1)[1])


@pytest.fixture
def duckdb_conn():
    conn = connect()
    yield conn
    conn.execute("SELECT httpserve_stop()")
    conn.close()


def get(port, query, headers=None, **params):
    params['q'] = query
    url = f"http://127.0.0.1:{port}/?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read().decode()


def status_of(port, query, headers=None):
    try:
        get(port, query, headers)
        return 200
    except urllib.error.HTTPError as e:
        return e.code


def test_start_and_query(duckdb_conn):
    port = start(duckdb_conn)
    assert json.loads(get(port, "SELECT 1 AS a, 2.5 AS b, 'x' AS c")) == {'a': 1, 'b': 2.5, 'c': 'x'}


def test_formats(duckdb_conn):
    port = start(duckdb_conn)
    assert get(port, "SELECT 1 AS a, 'x,y' AS b", default_format='CSV') == 'a,b\n1,"x,y"\n'
    compact = json.loads(get(port, "SELECT 1::INTEGER AS a", default_format='JSONCompact'))
    assert compact['data'] == [[1]]
    assert '<column name="a">1</column>' in get(port, "SELECT 1 AS a", default_format='XML')


def test_restart(duckdb_conn):
    for _ in range(3):
        port = start(duckdb_conn)
        assert get(port, "SELECT 1 AS a") == '{"a":1}\n'
        duckdb_conn.execute("SELECT httpserve_stop()")


def test_port_in_use_is_an_error(duckdb_conn):
    port = start(duckdb_conn)
    other = connect()
    try:
        with pytest.raises(duckdb.IOException, match='could not be bound'):
            start(other, port=port)
        # Both processes' databases keep working.
        assert other.execute("SELECT 42").fetchone()[0] == 42
        assert get(port, "SELECT 1 AS a") == '{"a":1}\n'
    finally:
        other.close()


def test_non_loopback_requires_auth(duckdb_conn):
    with pytest.raises(duckdb.PermissionException):
        start(duckdb_conn, host='0.0.0.0')


def test_api_key(duckdb_conn):
    port = start(duckdb_conn, auth='secret-key')
    assert status_of(port, "SELECT 1") == 401
    assert status_of(port, "SELECT 1", {'X-API-Key': 'wrong'}) == 401
    assert status_of(port, "SELECT 1", {'X-API-Key': 'secret-key'}) == 200


def test_basic_auth(duckdb_conn):
    port = start(duckdb_conn, auth='alice:s3cret')
    good = 'Basic ' + base64.b64encode(b'alice:s3cret').decode()
    assert status_of(port, "SELECT 1") == 401
    assert status_of(port, "SELECT 1", {'Authorization': good}) == 200
    assert status_of(port, "SELECT 1", {'X-API-Key': 'alice:s3cret'}) == 401


def test_cross_origin_is_refused(duckdb_conn):
    port = start(duckdb_conn)
    assert status_of(port, "SELECT 1", {'Origin': 'http://evil.example'}) == 403
    assert status_of(port, "SELECT 1", {'Host': 'evil.example'}) == 403
    assert status_of(port, "SELECT 1", {'Origin': f'http://127.0.0.1:{port}'}) == 200


def test_stop_from_served_query_is_refused(duckdb_conn):
    port = start(duckdb_conn)
    assert status_of(port, "SELECT httpserve_stop()") == 500
    assert get(port, "SELECT 1 AS a") == '{"a":1}\n'


def test_closing_the_database_stops_the_server():
    conn = connect()
    port = start(conn)
    conn.close()
    with pytest.raises(urllib.error.URLError):
        get(port, "SELECT 1")


def test_tls(duckdb_conn, tmp_path):
    import shutil
    import ssl
    import subprocess

    if not shutil.which('openssl'):
        pytest.skip('needs the openssl command to make a test certificate')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'], check=True, capture_output=True)
    duckdb_conn.execute(f"SET httpserver_tls_cert = '{cert}'")
    duckdb_conn.execute(f"SET httpserver_tls_key = '{key}'")
    message = duckdb_conn.execute("SELECT httpserve_start('127.0.0.1', 0, 'k')").fetchone()[0]
    assert message.startswith('HTTPS server started on')
    port = int(message.rsplit(':', 1)[1])
    context = ssl.create_default_context(cafile=str(cert))
    context.check_hostname = False
    request = urllib.request.Request(f"https://127.0.0.1:{port}/?q=SELECT%201%20AS%20a", headers={'X-API-Key': 'k'})
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        assert response.read().decode() == '{"a":1}\n'
