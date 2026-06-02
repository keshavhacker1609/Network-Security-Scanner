from pathlib import Path
import yaml


class Config:
    """Loads and validates config.yaml, providing typed accessors for each section."""

    _DEFAULT_PATH = Path(__file__).parent / "config.yaml"

    def __init__(self, path: str = None):
        config_path = Path(path) if path else self._DEFAULT_PATH
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "r", encoding="utf-8") as fh:
            self._data = yaml.safe_load(fh)

        self._validate()

    # ------------------------------------------------------------------ #
    # Validation                                                           #
    # ------------------------------------------------------------------ #

    def _validate(self):
        required = ["scanner", "logging", "output", "risk_database"]
        for section in required:
            if section not in self._data:
                raise ValueError(f"Missing required config section: '{section}'")

        if not isinstance(self._data["risk_database"], dict):
            raise ValueError("'risk_database' must be a mapping of port → attributes.")

    # ------------------------------------------------------------------ #
    # Accessors                                                            #
    # ------------------------------------------------------------------ #

    @property
    def scanner(self) -> dict:
        return self._data["scanner"]

    @property
    def logging_config(self) -> dict:
        return self._data["logging"]

    @property
    def output(self) -> dict:
        return self._data["output"]

    @property
    def risk_database(self) -> dict:
        # Ensure integer keys (YAML may parse them as ints already, but be explicit)
        return {int(k): v for k, v in self._data["risk_database"].items()}

    def get(self, *keys, default=None):
        """Safely traverse nested keys: config.get('scanner', 'timeout', default=300)."""
        node = self._data
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key)
            if node is None:
                return default
        return node
