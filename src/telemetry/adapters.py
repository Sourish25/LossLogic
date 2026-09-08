"""Telemetry ingestion adapters: Base abstract adapter and JSON, CSV, REST implementations."""

from abc import ABC, abstractmethod
import csv
import io
import json
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class TelemetryAdapter(ABC):
    """Abstract base adapter defining the contract for ingesting heterogeneous enterprise telemetry."""

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        """
        Parses raw ingested data (JSON, CSV, REST payload) into a list of standard dictionaries.
        
        Args:
            raw_data: Raw input data in format-specific representation.
            
        Returns:
            List of standardized dictionary records.
        """
        pass

    def parse_to_model(self, raw_data: Any, model_cls: Type[T]) -> List[T]:
        """
        Parses raw data and validates each record against a target Pydantic model.
        
        Args:
            raw_data: Raw input payload.
            model_cls: Pydantic model class to validate and instantiate.
            
        Returns:
            List of instantiated and validated Pydantic model objects.
        """
        records = self.parse(raw_data)
        validated_items: List[T] = []
        for r in records:
            validated_items.append(model_cls.model_validate(r))
        return validated_items


class JsonTelemetryAdapter(TelemetryAdapter):
    """
    Adapter for ingesting structured JSON telemetry payloads.
    Supports single JSON objects, lists of JSON objects, JSON strings, or wrapped dictionaries.
    """

    def parse(self, raw_data: Union[str, bytes, Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Parses JSON content into a list of dictionaries."""
        if raw_data is None:
            return []

        parsed: Any
        if isinstance(raw_data, (str, bytes)):
            text = raw_data.decode("utf-8") if isinstance(raw_data, bytes) else raw_data
            text = text.strip()
            if not text:
                return []
            parsed = json.loads(text)
        else:
            parsed = raw_data

        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        elif isinstance(parsed, dict):
            # Unwrap common container keys
            for wrapper_key in ("findings", "alerts", "data", "records", "items", "results"):
                if wrapper_key in parsed and isinstance(parsed[wrapper_key], list):
                    return [item for item in parsed[wrapper_key] if isinstance(item, dict)]
            return [parsed]
        else:
            raise ValueError(f"Unexpected JSON payload type: {type(parsed)}")


class CsvTelemetryAdapter(TelemetryAdapter):
    """
    Adapter for ingesting CSV tabular telemetry exports (e.g. vulnerability scanner reports).
    Performs type coercion for numbers and boolean flags.
    """

    def parse(self, raw_data: Union[str, io.StringIO, bytes]) -> List[Dict[str, Any]]:
        """Parses CSV text into a list of typed dictionaries."""
        if raw_data is None:
            return []

        csv_text: str
        if isinstance(raw_data, bytes):
            csv_text = raw_data.decode("utf-8")
        elif isinstance(raw_data, io.StringIO):
            csv_text = raw_data.getvalue()
        elif isinstance(raw_data, str):
            csv_text = raw_data
        else:
            raise ValueError(f"Unsupported CSV input type: {type(raw_data)}")

        csv_text = csv_text.strip()
        if not csv_text:
            return []

        reader = csv.DictReader(io.StringIO(csv_text))
        records: List[Dict[str, Any]] = []

        for row in reader:
            coerced_row: Dict[str, Any] = {}
            for k, v in row.items():
                if k is None:
                    continue
                clean_key = k.strip()
                clean_val = v.strip() if isinstance(v, str) else v
                coerced_row[clean_key] = self._coerce_value(clean_val)
            records.append(coerced_row)

        return records

    @staticmethod
    def _coerce_value(val: Any) -> Any:
        """Coerce string representations of numbers, booleans, and nulls into Python types."""
        if not isinstance(val, str) or val == "":
            return val
        lower_val = val.lower()
        if lower_val in ("true", "yes", "t", "y"):
            return True
        if lower_val in ("false", "no", "f", "n"):
            return False
        if lower_val in ("none", "null", "n/a", "nil"):
            return None

        # Check for integer
        try:
            if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
                return int(val)
        except ValueError:
            pass

        # Check for float
        try:
            return float(val)
        except ValueError:
            pass

        # Check for list representation (e.g., "[22, 443]" or "22;443")
        if (val.startswith("[") and val.endswith("]")) or ";" in val:
            try:
                inner = val.strip("[]")
                delimiter = ";" if ";" in inner else ","
                parts = [p.strip() for p in inner.split(delimiter) if p.strip()]
                return [CsvTelemetryAdapter._coerce_value(p) for p in parts]
            except Exception:
                pass

        return val


class RestTelemetryAdapter(TelemetryAdapter):
    """
    Adapter for ingesting RESTful API payloads (webhooks, poll responses, structured JSON envelopes).
    Handles pagination containers, metadata wrappers, and nested attribute trees.
    """

    def __init__(self, data_key: Optional[str] = None):
        """
        Args:
            data_key: Optional specific key in response containing finding items.
        """
        self.data_key = data_key

    def parse(self, raw_data: Union[Dict[str, Any], List[Dict[str, Any]], str]) -> List[Dict[str, Any]]:
        """Parses REST response dictionary or JSON string into finding records."""
        payload: Any
        if isinstance(raw_data, str):
            payload = json.loads(raw_data)
        else:
            payload = raw_data

        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if isinstance(payload, dict):
            # If explicit data_key configured, extract from it
            if self.data_key and self.data_key in payload:
                extracted = payload[self.data_key]
                if isinstance(extracted, list):
                    return [item for item in extracted if isinstance(item, dict)]
                elif isinstance(extracted, dict):
                    return [extracted]

            # Standard REST envelope fields inspection
            for candidate in ("data", "results", "payload", "items", "records", "alerts", "findings"):
                if candidate in payload and isinstance(payload[candidate], list):
                    return [item for item in payload[candidate] if isinstance(item, dict)]

            # Check if payload itself represents a single finding
            return [payload]

        raise ValueError(f"Cannot parse REST payload of type: {type(payload)}")
