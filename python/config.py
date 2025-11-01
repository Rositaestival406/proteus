import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class ProteusConfig:
    api_key: str
    output_dir: str = "dataset/malicious"
    rate_limit_requests: int = 10
    rate_limit_window: float = 60.0
    timeout_seconds: int = 30
    retry_attempts: int = 2
    samples_per_tag: int = 50
    max_file_size_mb: int = 100
    verbose: bool = False


class ConfigManager:

    CONFIG_DIR = Path.home() / ".proteus"
    CONFIG_FILE = CONFIG_DIR / "config.json"

    @staticmethod
    def load_api_key() -> str:
        api_key = os.getenv("MALWAREBAZAAR_API_KEY")
        if api_key:
            return api_key

        if ConfigManager.CONFIG_FILE.exists():
            try:
                with open(ConfigManager.CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    api_key = config.get("api_key", "")
                    if api_key:
                        return api_key
            except (json.JSONDecodeError, IOError):
                pass

        return ""

    @staticmethod
    def save_api_key(api_key: str) -> bool:
        try:
            ConfigManager.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

            config = {}
            if ConfigManager.CONFIG_FILE.exists():
                with open(ConfigManager.CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)

            config["api_key"] = api_key

            with open(ConfigManager.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)

            return True

        except (IOError, json.JSONDecodeError):
            return False

    @staticmethod
    def load_config() -> Dict[str, Any]:
        config = {
            "rate_limit_requests": 10,
            "rate_limit_window": 60.0,
            "timeout_seconds": 30,
            "retry_attempts": 2,
            "samples_per_tag": 50,
            "max_file_size_mb": 100,
            "verbose": False,
        }

        if ConfigManager.CONFIG_FILE.exists():
            try:
                with open(ConfigManager.CONFIG_FILE, "r", encoding="utf-8") as f:
                    user_config = json.load(f)
                    config.update(user_config)
            except (json.JSONDecodeError, IOError):
                pass

        for key in config.keys():
            env_key = f"PROTEUS_{key.upper()}"
            env_value = os.getenv(env_key)
            if env_value:
                current_val = config[key]
                if isinstance(current_val, int):
                    config[key] = int(env_value)
                elif isinstance(current_val, float):
                    config[key] = float(env_value)
                elif isinstance(current_val, bool):
                    config[key] = env_value.lower() in ("true", "1", "yes")
                else:
                    config[key] = env_value

        return config

    @staticmethod
    def create_proteus_config(api_key: Optional[str] = None) -> ProteusConfig:
        if not api_key:
            api_key = ConfigManager.load_api_key()

        config_dict = ConfigManager.load_config()

        return ProteusConfig(
            api_key=api_key,
            output_dir=config_dict.get("output_dir", "dataset/malicious"),
            rate_limit_requests=config_dict.get("rate_limit_requests", 10),
            rate_limit_window=config_dict.get("rate_limit_window", 60.0),
            timeout_seconds=config_dict.get("timeout_seconds", 30),
            retry_attempts=config_dict.get("retry_attempts", 2),
            samples_per_tag=config_dict.get("samples_per_tag", 50),
            max_file_size_mb=config_dict.get("max_file_size_mb", 100),
            verbose=config_dict.get("verbose", False),
        )
