"""Target parsing: one parser for HTTP origins, datastores and the local host."""

from __future__ import annotations

import pytest

from relift.models import Target, database_engine


def test_bare_hostname_defaults_to_https_443():
    target = Target.parse("example.com")
    assert target.scheme == "https"
    assert target.port == 443
    assert target.path == "/"
    assert target.kind == "http"
    assert target.families == ("http",)


def test_http_default_port_and_explicit_port():
    assert Target.parse("http://example.com").port == 80
    target = Target.parse("http://example.com:8080/x?y=1")
    assert target.port == 8080
    assert target.path == "/x?y=1"


def test_origin_renders_with_and_without_default_port():
    assert Target.parse("https://example.com").origin == "https://example.com/"
    assert Target.parse("http://example.com:8080").origin == "http://example.com:8080/"


def test_postgres_scheme_is_a_database_target():
    target = Target.parse("postgres://127.0.0.1")
    assert target.engine == "postgres"
    assert target.kind == "db"
    assert target.port == 5432
    assert target.families == ("db",)


def test_postgresql_alias_and_database_name():
    target = Target.parse("postgresql://db.internal:6432/appdb")
    assert target.engine == "postgres"
    assert target.port == 6432
    assert target.database_name == "appdb"
    assert target.origin == "postgresql://db.internal:6432/appdb"


def test_mariadb_is_normalised_to_mysql():
    target = Target.parse("mariadb://127.0.0.1:3307")
    assert target.engine == "mysql"
    assert target.port == 3307


def test_mongodb_default_port():
    target = Target.parse("mongodb://127.0.0.1")
    assert target.engine == "mongodb"
    assert target.port == 27017
    assert target.kind == "db"


def test_sqlserver_alias_maps_to_mssql():
    assert Target.parse("sqlserver://127.0.0.1").engine == "mssql"
    assert Target.parse("tds://127.0.0.1").port == 1433


def test_redis_scheme():
    assert Target.parse("redis://127.0.0.1:6380").engine == "redis"
    assert Target.parse("rediss://127.0.0.1").port == 6379


def test_http_speaking_datastore_belongs_to_both_families():
    target = Target.parse("elasticsearch://127.0.0.1")
    assert target.engine == "elasticsearch"
    assert target.kind == "http"
    assert target.families == ("http", "db")
    assert target.port == 9200


def test_local_target_is_the_host_family():
    target = Target.parse("local://")
    assert target.kind == "host"
    assert target.host == "127.0.0.1"
    assert target.port == 0
    assert target.families == ("host",)
    assert target.origin == "local://127.0.0.1"


def test_local_shorthand():
    assert Target.parse("local").kind == "host"


def test_ssh_target():
    target = Target.parse("ssh://10.0.0.5")
    assert target.kind == "ssh"
    assert target.port == 22
    assert target.families == ("ssh",)
    assert target.origin == "ssh://10.0.0.5:22"


def test_database_name_is_empty_for_http_targets():
    assert Target.parse("https://example.com/app").database_name == ""


def test_unknown_scheme_is_refused():
    with pytest.raises(ValueError, match="unsupported scheme"):
        Target.parse("ftp://example.com")


def test_empty_target_is_refused():
    with pytest.raises(ValueError, match="empty target"):
        Target.parse("   ")


def test_out_of_range_port_is_refused():
    with pytest.raises(ValueError, match="bad port"):
        Target.parse("http://example.com:99999")


def test_to_dict_exposes_engine_and_families():
    payload = Target.parse("mysql://127.0.0.1:3306/shop").to_dict()
    assert payload["engine"] == "mysql"
    assert payload["kind"] == "db"
    assert payload["families"] == ["db"]


def test_database_engine_helper_is_case_insensitive():
    assert database_engine("PostgreSQL") == "postgres"
    assert database_engine("ES") == "elasticsearch"
    assert database_engine("https") == ""
