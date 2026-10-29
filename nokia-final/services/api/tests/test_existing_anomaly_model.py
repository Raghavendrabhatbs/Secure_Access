import sys
from types import ModuleType
from pathlib import Path
import unittest
from unittest.mock import patch

AGENT_ROOT = Path(__file__).resolve().parents[2] / "agent"
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))
_previous_psycopg2 = sys.modules.get("psycopg2")
sys.modules["psycopg2"] = ModuleType("psycopg2")
try:
    from anomaly_detector import MODEL_PATH, load_model, score_live_session
finally:
    if _previous_psycopg2 is None:
        sys.modules.pop("psycopg2", None)
    else:
        sys.modules["psycopg2"] = _previous_psycopg2
from sklearn.ensemble import IsolationForest


class ExistingAnomalyModelTest(unittest.TestCase):
    def test_saved_model_loads_and_scores_without_retraining(self):
        self.assertTrue(Path(MODEL_PATH).is_file())
        with patch("anomaly_detector.train_model", side_effect=AssertionError("must not retrain")):
            model = load_model()

        self.assertIsInstance(model, IsolationForest)
        self.assertEqual(model.n_features_in_, 8)
        result = score_live_session(
            model,
            hour=9,
            day_of_week=1,
            duration_seconds=180,
            total_commands=5,
            sudo_count=0,
            has_history_clear=0,
            has_dangerous_cmd=0,
            commands_per_minute=1.7,
        )

        self.assertIsInstance(result["score"], float)
        self.assertIsInstance(result["is_anomaly"], bool)
        self.assertIn(result["label"], {"NORMAL", "SUSPICIOUS", "ANOMALOUS", "HIGHLY_ANOMALOUS"})


if __name__ == "__main__":
    unittest.main()