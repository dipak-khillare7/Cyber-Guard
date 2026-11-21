import os
import sys

# Ensure workspace root is accessible
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.inference.predictor import ThreatPredictor as MLThreatPredictor

class ThreatPredictor(MLThreatPredictor):
    """
    Backend wrapper around production ML inference engine.
    """
    pass
