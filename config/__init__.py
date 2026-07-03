from pathlib import Path
import yaml


class Config:
    """Loads and validates config.yaml, providing typed accessors for each section.

    The risk database is modular: it is assembled from any files listed under
    ``risk_database_files`` (resolved relative to the config file) merged in
    order, with an optional inline ``risk_database`` block applied last.
    """

    _DEFAULT_PATH = Path(__file__).parent / "config.yaml"

    def __init__(self, path: str = None):
        config_path = Path(path) if path else self._DEFAULT_PATH
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        self._path = config_path
        with open(config_path, "r", encoding="utf-8") as fh:
            self._data = yaml.safe_load(fh) or {}

        self._risk_database = self._load_risk_database()
        self._validate()

    # ------------------------------------------------------------------ #
    # Risk-database assembly                                                #
    # ------------------------------------------------------------------ #

    def _load_risk_database(self) -> dict:
        """Merge every referenced risk-database file plus the inline block."""
        base_dir = self._path.parent
        merged: dict = {}

        for rel in self._data.get("risk_database_files", []) or []:
            db_path = (base_dir / rel).resolve()
            if not db_path.exists():
                raise FileNotFoundError(f"Referenced risk_database file not found: {db_path}")
            with open(db_path, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            entries = loaded.get("risk_database", loaded)
            if not isinstance(entries, dict):
                raise ValueError(f"'risk_database' in {db_path} must be a mapping of port -> attributes.")
            merged.update({int(k): v for k, v in entries.items()})

        inline = self._data.get("risk_database") or {}
        if not isinstance(inline, dict):
            raise ValueError("Inline 'risk_database' must be a mapping of port -> attributes.")
        merged.update({int(k): v for k, v in inline.items()})

        return merged

    # ------------------------------------------------------------------ #
    # Validation                                                           #
    # ------------------------------------------------------------------ #

    def _validate(self):
        required = ["scanner", "logging", "output"]
        for section in required:
            if section not in self._data:
                raise ValueError(f"Missing required config section: '{section}'")

        if not self._risk_database:
            raise ValueError(
                "Risk database is empty. Populate 'risk_database.yaml' or an inline "
                "'risk_database' block in config.yaml."
            )

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
    def history(self) -> dict:
        return self._data.get("history", {})

    @property
    def ci(self) -> dict:
        return self._data.get("ci", {})

    @property
    def risk_database(self) -> dict:
        return self._risk_database

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
