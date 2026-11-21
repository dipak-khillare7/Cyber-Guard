"""
Centralized hyperparameter and experiment configuration for ML candidate training.
"""
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier

RANDOM_SEED = 42

EXPERIMENT_MODELS = {
    "LogisticRegression": {
        "class": LogisticRegression,
        "params": {
            "max_iter": 1000,
            "class_weight": "balanced",
            "random_state": RANDOM_SEED
        }
    },
    "DecisionTree": {
        "class": DecisionTreeClassifier,
        "params": {
            "max_depth": 15,
            "class_weight": "balanced",
            "random_state": RANDOM_SEED
        }
    },
    "RandomForest": {
        "class": RandomForestClassifier,
        "params": {
            "n_estimators": 100,
            "max_depth": 15,
            "class_weight": "balanced",
            "random_state": RANDOM_SEED,
            "n_jobs": -1
        }
    },
    "HistGradientBoosting": {
        "class": HistGradientBoostingClassifier,
        "params": {
            "max_iter": 100,
            "random_state": RANDOM_SEED
        }
    }
}
