"""Tests for exec_chunk config fields (issue #116)."""

from __future__ import annotations

import pytest
from hermes_node_plugin.errors import ConfigError

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

class TestExecChunkDefaults:
    def test_defaults(self) -> None:
        from hermes_node_plugin.config import NodeServerConfig

        cfg = NodeServerConfig()
        assert cfg.exec_chunk_dir == "/tmp/hermes-exec-chunks"
        assert cfg.exec_chunk_max_total_mb == 50
        assert cfg.exec_chunk_timeout_s == 30
        assert cfg.exec_chunk_size == 65536


# ---------------------------------------------------------------------------
# Env overrides
# ---------------------------------------------------------------------------

class TestExecChunkEnvOverrides:
    def test_env_overrides_all(self) -> None:
        from hermes_node_plugin.config import load_config

        env = {
            "HERMES_NODES_EXEC_CHUNK_DIR": "/tmp/my-chunks",
            "HERMES_NODES_EXEC_CHUNK_MAX_TOTAL_MB": "100",
            "HERMES_NODES_EXEC_CHUNK_TIMEOUT_S": "60",
            "HERMES_NODES_EXEC_CHUNK_SIZE": "131072",
        }
        cfg = load_config(env=env)
        assert cfg.exec_chunk_dir == "/tmp/my-chunks"
        assert cfg.exec_chunk_max_total_mb == 100
        assert cfg.exec_chunk_timeout_s == 60
        assert cfg.exec_chunk_size == 131072

    def test_env_override_dir(self) -> None:
        from hermes_node_plugin.config import load_config

        cfg = load_config(env={"HERMES_NODES_EXEC_CHUNK_DIR": "/tmp/test-chunks"})
        assert cfg.exec_chunk_dir == "/tmp/test-chunks"

    def test_env_override_max_total_mb_unlimited(self) -> None:
        from hermes_node_plugin.config import load_config

        cfg = load_config(env={"HERMES_NODES_EXEC_CHUNK_MAX_TOTAL_MB": "0"})
        assert cfg.exec_chunk_max_total_mb == 0

    def test_env_override_max_total_mb_negative(self) -> None:
        from hermes_node_plugin.config import load_config

        cfg = load_config(env={"HERMES_NODES_EXEC_CHUNK_MAX_TOTAL_MB": "-1"})
        assert cfg.exec_chunk_max_total_mb == -1


# ---------------------------------------------------------------------------
# YAML file overrides
# ---------------------------------------------------------------------------

class TestExecChunkYamlOverrides:
    def test_yaml_overrides(self, tmp_path) -> None:
        from hermes_node_plugin.config import load_config

        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            "exec_chunk_dir: /tmp/yaml-chunks\n"
            "exec_chunk_max_total_mb: 200\n"
            "exec_chunk_timeout_s: 90\n"
            "exec_chunk_size: 32768\n"
        )
        cfg = load_config(config_path=str(yaml_path), env={})
        assert cfg.exec_chunk_dir == "/tmp/yaml-chunks"
        assert cfg.exec_chunk_max_total_mb == 200
        assert cfg.exec_chunk_timeout_s == 90
        assert cfg.exec_chunk_size == 32768

    def test_yaml_uppercase_keys(self, tmp_path) -> None:
        from hermes_node_plugin.config import load_config

        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            "EXEC_CHUNK_DIR: /tmp/yaml-upper\n"
            "EXEC_CHUNK_TIMEOUT_S: 45\n"
        )
        cfg = load_config(config_path=str(yaml_path), env={})
        assert cfg.exec_chunk_dir == "/tmp/yaml-upper"
        assert cfg.exec_chunk_timeout_s == 45


# ---------------------------------------------------------------------------
# Env beats yaml
# ---------------------------------------------------------------------------

class TestExecChunkEnvBeatsYaml:
    def test_env_beats_yaml(self, tmp_path) -> None:
        from hermes_node_plugin.config import load_config

        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(
            "exec_chunk_dir: /tmp/yaml-chunks\n"
            "exec_chunk_timeout_s: 90\n"
        )
        env = {
            "HERMES_NODES_EXEC_CHUNK_DIR": "/tmp/env-chunks",
            "HERMES_NODES_EXEC_CHUNK_TIMEOUT_S": "45",
        }
        cfg = load_config(config_path=str(yaml_path), env=env)
        assert cfg.exec_chunk_dir == "/tmp/env-chunks"
        assert cfg.exec_chunk_timeout_s == 45


# ---------------------------------------------------------------------------
# Rejects invalid values
# ---------------------------------------------------------------------------

class TestExecChunkRejects:
    def test_rejects_negative_timeout(self) -> None:
        from hermes_node_plugin.config import NodeServerConfig

        with pytest.raises(ConfigError):
            NodeServerConfig(exec_chunk_timeout_s=-1)

    def test_rejects_zero_timeout(self) -> None:
        from hermes_node_plugin.config import NodeServerConfig

        with pytest.raises(ConfigError):
            NodeServerConfig(exec_chunk_timeout_s=0)

    def test_rejects_zero_chunk_size(self) -> None:
        from hermes_node_plugin.config import NodeServerConfig

        with pytest.raises(ConfigError):
            NodeServerConfig(exec_chunk_size=0)

    def test_rejects_negative_chunk_size(self) -> None:
        from hermes_node_plugin.config import NodeServerConfig

        with pytest.raises(ConfigError):
            NodeServerConfig(exec_chunk_size=-1)

    def test_env_rejects_zero_timeout(self) -> None:
        from hermes_node_plugin.config import load_config

        with pytest.raises(ConfigError):
            load_config(env={"HERMES_NODES_EXEC_CHUNK_TIMEOUT_S": "0"})

    def test_env_rejects_zero_chunk_size(self) -> None:
        from hermes_node_plugin.config import load_config

        with pytest.raises(ConfigError):
            load_config(env={"HERMES_NODES_EXEC_CHUNK_SIZE": "0"})

    def test_env_rejects_non_integer_max_total(self) -> None:
        from hermes_node_plugin.config import load_config

        with pytest.raises(ConfigError):
            load_config(env={"HERMES_NODES_EXEC_CHUNK_MAX_TOTAL_MB": "nan"})


# ---------------------------------------------------------------------------
# Empty env string falls through to default
# ---------------------------------------------------------------------------

class TestExecChunkEmptyString:
    def test_empty_env_max_total_falls_through(self) -> None:
        from hermes_node_plugin.config import load_config

        cfg = load_config(env={"HERMES_NODES_EXEC_CHUNK_MAX_TOTAL_MB": ""})
        assert cfg.exec_chunk_max_total_mb == 50  # default

    def test_empty_env_timeout_falls_through(self) -> None:
        from hermes_node_plugin.config import load_config

        cfg = load_config(env={"HERMES_NODES_EXEC_CHUNK_TIMEOUT_S": ""})
        assert cfg.exec_chunk_timeout_s == 30  # default
