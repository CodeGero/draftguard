"""Tests for the multi-format config parser."""

import json
from pathlib import Path

import pytest

from draftguard.parser import ConfigParser, ParsedConfig


class TestConfigParser:
    """Tests for ConfigParser."""

    def test_infer_format_env(self):
        assert ConfigParser.infer_format(Path(".env")) == "env"
        assert ConfigParser.infer_format(Path(".env.production")) == "env"

    def test_infer_format_yaml(self):
        assert ConfigParser.infer_format(Path("config.yaml")) == "yaml"
        assert ConfigParser.infer_format(Path("app/config.yml")) == "yaml"

    def test_infer_format_json(self):
        assert ConfigParser.infer_format(Path("appsettings.json")) == "json"

    def test_infer_format_toml(self):
        assert ConfigParser.infer_format(Path("config.toml")) == "toml"

    def test_infer_format_docker_compose(self):
        assert ConfigParser.infer_format(Path("docker-compose.yml")) == "docker-compose"
        assert ConfigParser.infer_format(Path("docker-compose.prod.yaml")) == "docker-compose"

    def test_infer_format_k8s(self):
        assert ConfigParser.infer_format(Path("configmap.yaml")) == "k8s-configmap"
        assert ConfigParser.infer_format(Path("secret.yml")) == "k8s-secret"

    def test_infer_environment_dev_from_filename(self):
        assert ConfigParser.infer_environment(Path("/app/.env.dev")) == "dev"
        assert ConfigParser.infer_environment(Path(".env.development")) == "dev"

    def test_infer_environment_prod_from_filename(self):
        assert ConfigParser.infer_environment(Path(".env.production")) == "prod"
        assert ConfigParser.infer_environment(Path(".env.prod")) == "prod"

    def test_infer_environment_staging_from_filename(self):
        assert ConfigParser.infer_environment(Path(".env.staging")) == "staging"

    def test_infer_environment_from_dir_name(self):
        assert ConfigParser.infer_environment(Path("dev/.env")) == "dev"
        assert ConfigParser.infer_environment(Path("production/.env")) == "prod"
        assert ConfigParser.infer_environment(Path("staging/config.yaml")) == "staging"

    def test_infer_environment_example(self):
        assert ConfigParser.infer_environment(Path(".env.example")) == "example"

    def test_parse_env_file(self, dev_env_file):
        parser = ConfigParser()
        result = parser.parse(dev_env_file)

        assert result.format == "env"
        assert result.env_name == "dev"
        assert "DATABASE_URL" in result.values
        assert "SECRET_KEY" in result.values
        assert result.values["DEBUG"] == "true"

    def test_parse_env_file_has_expected_keys(self, prod_env_file):
        parser = ConfigParser()
        result = parser.parse(prod_env_file)

        assert result.values["DATABASE_URL"].startswith("postgresql://")
        assert result.values["DEBUG"] == "false"
        assert result.values["NODE_ENV"] == "production"

    def test_parse_yaml_file(self, dev_dir):
        parser = ConfigParser()
        yaml_file = dev_dir / "config.yaml"
        result = parser.parse(yaml_file)

        assert result.format == "yaml"
        assert "database.url" in result.values
        assert result.values["app.debug"] == "true"

    def test_parse_json_file(self, tmp_path):
        json_file = tmp_path / "config.json"
        json_file.write_text(json.dumps({
            "server": {"host": "0.0.0.0", "port": 8080},
            "debug": True,
        }))

        parser = ConfigParser()
        result = parser.parse(json_file)

        assert result.format == "json"
        assert result.values["server.host"] == "0.0.0.0"
        assert result.values["server.port"] == "8080"
        assert result.values["debug"] == "true"

    def test_parse_toml_file(self, tmp_path):
        toml_file = tmp_path / "config.toml"
        toml_file.write_text("""
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "postgresql://localhost/db"
""")

        parser = ConfigParser()
        result = parser.parse(toml_file)

        assert result.format == "toml"
        assert "server.host" in result.values
        assert result.values["server.port"] == "8080"

    def test_parse_docker_compose(self, tmp_path):
        dc_file = tmp_path / "docker-compose.yml"
        dc_file.write_text("""
version: "3"
services:
  web:
    image: myapp
    environment:
      DATABASE_URL: postgresql://db:5432/app
      REDIS_URL: redis://redis:6379
      DEBUG: "false"
  worker:
    environment:
      - QUEUE=default
      - CONCURRENCY=4
""")

        parser = ConfigParser()
        result = parser.parse(dc_file)

        assert result.format == "docker-compose"
        assert result.values["web.DATABASE_URL"] == "postgresql://db:5432/app"
        assert result.values["web.REDIS_URL"] == "redis://redis:6379"
        assert result.values["worker.QUEUE"] == "default"

    def test_parse_k8s_configmap(self, tmp_path):
        k8s_file = tmp_path / "configmap.yaml"
        k8s_file.write_text("""
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_URL: postgresql://db:5432/app
  LOG_LEVEL: info
""")

        parser = ConfigParser()
        result = parser.parse(k8s_file)

        assert result.format == "k8s-configmap"
        assert result.values["DATABASE_URL"] == "postgresql://db:5432/app"
        assert result.values["LOG_LEVEL"] == "info"

    def test_parse_k8s_secret(self, tmp_path):
        k8s_file = tmp_path / "secret.yaml"
        k8s_file.write_text("""
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
stringData:
  API_KEY: sk-super-secret
  DB_PASSWORD: secure-password
""")

        parser = ConfigParser()
        result = parser.parse(k8s_file)

        assert result.format == "k8s-secret"
        assert result.values["API_KEY"] == "sk-super-secret"
        assert result.values["DB_PASSWORD"] == "secure-password"

    def test_parse_unknown_format(self, tmp_path):
        unknown_file = tmp_path / "something.xyz"
        unknown_file.write_text("foo=bar")

        parser = ConfigParser()
        result = parser.parse(unknown_file)

        assert result.format == "unknown"
        assert len(result.errors) > 0

    def test_parse_empty_file(self, tmp_path):
        empty_file = tmp_path / ".env"
        empty_file.write_text("")

        parser = ConfigParser()
        result = parser.parse(empty_file)

        assert len(result.values) == 0

    def test_parse_directory(self, fixtures_dir):
        parser = ConfigParser()
        results = parser.parse_directory(fixtures_dir)

        assert len(results) > 0
        formats = {r.format for r in results}
        assert "env" in formats or "yaml" in formats

    def test_is_expected_diff(self):
        assert ConfigParser.is_expected_diff("DATABASE_URL") is True
        assert ConfigParser.is_expected_diff("DEBUG") is True
        assert ConfigParser.is_expected_diff("SECRET_KEY") is False

    def test_flatten_list_items(self, tmp_path):
        json_file = tmp_path / "config.json"
        json_file.write_text(json.dumps({
            "hosts": ["host1", "host2", "host3"],
        }))

        parser = ConfigParser()
        result = parser.parse(json_file)

        assert result.values["hosts.0"] == "host1"
        assert result.values["hosts.1"] == "host2"
        assert result.values["hosts.2"] == "host3"

    def test_error_on_bad_yaml(self, tmp_path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text(": invalid: yaml: :")

        parser = ConfigParser()
        result = parser.parse(bad_yaml)

        assert len(result.errors) > 0
