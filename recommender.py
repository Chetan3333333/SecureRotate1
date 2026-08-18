"""
Password Recommendation & ML Engine
------------------------------------

Responsibilities:
1. Extract password security features
2. Detect predictable patterns
3. Generate synthetic training data
4. Train Random Forest model
5. Analyze passwords
6. Calculate security score
7. Identify risks
8. Generate ranked recommendations

IMPORTANT:
- Plaintext passwords are never saved to the dataset.
- The ML model works on extracted security features.
"""

import math
import random
import re
import string
from collections import Counter

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


# =========================================================
# CONFIGURATION
# =========================================================

MODEL_FILE = "password_model.pkl"

FEATURE_COLUMNS = [
    "length",
    "uppercase_count",
    "lowercase_count",
    "digit_count",
    "special_count",
    "unique_character_ratio",
    "repetition_ratio",
    "sequential_pattern",
    "keyboard_pattern",
    "common_password",
    "dictionary_word",
    "substitution_pattern",
    "year_pattern",
    "entropy",
]


# =========================================================
# SECURITY KNOWLEDGE
# =========================================================

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "cricket",
    "abc123",
    "password1",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
}

COMMON_WORDS = {
    "password",
    "admin",
    "welcome",
    "qwerty",
    "football",
    "cricket",
    "dragon",
    "monkey",
    "summer",
    "winter",
    "spring",
    "autumn",
    "love",
    "hello",
    "computer",
    "python",
    "india",
    "tiger",
    "shadow",
    "master",
    "login",
    "secret",
    "user",
}

SUBSTITUTIONS = {
    "@": "a",
    "4": "a",
    "3": "e",
    "1": "i",
    "!": "i",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
}


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def calculate_entropy(password):

    if not password:
        return 0.0

    pool_size = 0

    if re.search(r"[a-z]", password):
        pool_size += 26

    if re.search(r"[A-Z]", password):
        pool_size += 26

    if re.search(r"[0-9]", password):
        pool_size += 10

    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 33

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def calculate_unique_ratio(password):

    if not password:
        return 0.0

    return len(set(password)) / len(password)


def calculate_repetition_ratio(password):

    if not password:
        return 0.0

    counts = Counter(password)

    repeated = sum(
        count - 1
        for count in counts.values()
        if count > 1
    )

    return repeated / len(password)


def detect_sequential_pattern(password):

    password = password.lower()

    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]

    for sequence in sequences:

        for i in range(len(sequence) - 2):

            pattern = sequence[i:i + 3]

            if pattern in password:
                return 1

            if pattern[::-1] in password:
                return 1

    return 0


def detect_keyboard_pattern(password):

    password = password.lower()

    keyboard_patterns = [
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "qaz",
        "wsx",
        "edc",
        "rfv",
        "tgb",
    ]

    for pattern in keyboard_patterns:

        if pattern in password:
            return 1

        if pattern[::-1] in password:
            return 1

    return 0


def detect_common_password(password):

    return int(
        password.lower() in COMMON_PASSWORDS
    )


def detect_dictionary_word(password):

    normalized = password.lower()

    cleaned = re.sub(
        r"[^a-z]",
        "",
        normalized
    )

    if cleaned in COMMON_WORDS:
        return 1

    for word in COMMON_WORDS:

        if len(word) >= 5 and word in cleaned:
            return 1

    return 0


def detect_substitution_pattern(password):

    normalized = password.lower()

    converted = ""
    substitution_count = 0

    for character in normalized:

        if character in SUBSTITUTIONS:

            converted += SUBSTITUTIONS[character]
            substitution_count += 1

        else:
            converted += character

    if substitution_count == 0:
        return 0

    for word in COMMON_WORDS:

        if word in converted:
            return 1

    return 0


def detect_year_pattern(password):

    years = re.findall(
        r"(19\d{2}|20\d{2})",
        password
    )

    return int(bool(years))


def extract_features(password):

    if not isinstance(password, str):
        raise TypeError(
            "Password must be a string."
        )

    if not password:
        raise ValueError(
            "Password cannot be empty."
        )

    return {

        "length": len(password),

        "uppercase_count": sum(
            c.isupper()
            for c in password
        ),

        "lowercase_count": sum(
            c.islower()
            for c in password
        ),

        "digit_count": sum(
            c.isdigit()
            for c in password
        ),

        "special_count": sum(
            not c.isalnum()
            for c in password
        ),

        "unique_character_ratio":
            calculate_unique_ratio(password),

        "repetition_ratio":
            calculate_repetition_ratio(password),

        "sequential_pattern":
            detect_sequential_pattern(password),

        "keyboard_pattern":
            detect_keyboard_pattern(password),

        "common_password":
            detect_common_password(password),

        "dictionary_word":
            detect_dictionary_word(password),

        "substitution_pattern":
            detect_substitution_pattern(password),

        "year_pattern":
            detect_year_pattern(password),

        "entropy":
            calculate_entropy(password),
    }


# =========================================================
# TRAINING DATA GENERATORS
# =========================================================

COMMON_WORD_LIST = list(COMMON_WORDS)


def generate_weak_password():

    return random.choice([
        "123456",
        "12345678",
        "123456789",
        "password",
        "password123",
        "qwerty",
        "qwerty123",
        "admin",
        "admin123",
        "welcome",
        "welcome123",
        "letmein",
        "abc123",
        "iloveyou",
        "111111",
        "000000",
    ])


def generate_predictable_password():

    word = random.choice(
        COMMON_WORD_LIST
    )

    return random.choice([

        word + str(
            random.randint(10, 9999)
        ),

        word.capitalize()
        + "@"
        + str(
            random.randint(10, 9999)
        ),

        word.capitalize()
        + "#"
        + str(
            random.randint(100, 9999)
        ),

        word.capitalize() + "123",

        word.capitalize() + "@123",

        word.capitalize() + "2026",
    ])


def generate_substitution_password():

    return random.choice([
        "P@ssw0rd",
        "P@ssword123",
        "P@ssw0rd123",
        "Adm1n@123",
        "W3lcome@123",
        "Qw3rty@123",
        "Passw0rd!",
        "H3llo@123",
    ])


def generate_keyboard_password():

    return random.choice([
        "qwerty123",
        "qwerty@123",
        "asdfgh123",
        "asdf@123",
        "zxcvbn123",
        "qazwsx123",
        "qwertyuiop",
        "asdfghjkl",
    ])


def generate_repetitive_password():

    return random.choice([
        "aaaaaaaa",
        "aaaaaaaaaaaa",
        "11111111",
        "0000000000",
        "abababab",
        "abcabcabc",
        "12121212",
        "aaaa1234",
        "xxxxPasswordxxxx",
    ])


def generate_medium_password():

    word = random.choice(
        COMMON_WORD_LIST
    )

    number = random.randint(
        100,
        999999
    )

    special = random.choice(
        ["@", "#", "$", "!"]
    )

    return random.choice([

        word.capitalize()
        + special
        + str(number),

        word
        + str(number)
        + special,

        word.capitalize()
        + str(number)
        + "X",
    ])


def generate_strong_password():

    length = random.randint(
        14,
        22
    )

    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    password = [

        random.choice(
            string.ascii_uppercase
        ),

        random.choice(
            string.ascii_lowercase
        ),

        random.choice(
            string.digits
        ),

        random.choice(
            "!@#$%^&*()-_=+"
        ),
    ]

    password += random.choices(
        characters,
        k=length - 4
    )

    random.shuffle(password)

    return "".join(password)


def generate_strong_passphrase():

    words = random.sample(
        [
            "violet",
            "orbit",
            "canyon",
            "silver",
            "meteor",
            "forest",
            "quantum",
            "falcon",
            "nebula",
            "crystal",
            "matrix",
            "thunder",
            "ocean",
            "rocket",
        ],
        4
    )

    separator = random.choice(
        ["-", "_", ".", "!"]
    )

    number = random.randint(
        10,
        999
    )

    return (
        separator.join(words)
        + separator
        + str(number)
    )


# =========================================================
# DATASET GENERATION
# =========================================================

def generate_training_dataset(
    samples_per_category=500
):

    rows = []

    categories = [

        ("Weak", generate_weak_password),

        ("Weak", generate_predictable_password),

        ("Weak", generate_substitution_password),

        ("Weak", generate_keyboard_password),

        ("Weak", generate_repetitive_password),

        ("Medium", generate_medium_password),

        ("Strong", generate_strong_password),

        ("Strong", generate_strong_passphrase),
    ]

    for label, generator in categories:

        for _ in range(
            samples_per_category
        ):

            password = generator()

            features = extract_features(
                password
            )

            # IMPORTANT:
            # Only features are stored.
            # The original password is discarded.

            features["strength"] = label

            rows.append(features)

    dataset = pd.DataFrame(rows)

    return dataset.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)


# =========================================================
# ML MODEL
# =========================================================

class PasswordMLModel:

    def __init__(self):

        self.model = None

    def train(self):

        print(
            "Generating password security dataset..."
        )

        dataset = generate_training_dataset()

        X = dataset[
            FEATURE_COLUMNS
        ]

        y = dataset[
            "strength"
        ]

        print(
            f"Training samples: {len(dataset)}"
        )

        self.model = RandomForestClassifier(

            n_estimators=400,

            max_depth=None,

            min_samples_split=2,

            min_samples_leaf=1,

            class_weight="balanced",

            random_state=42,

            n_jobs=-1,
        )

        self.model.fit(
            X,
            y
        )

        print(
            "ML model trained successfully."
        )

        return self.model

    def load_or_train(self):

        try:

            self.model = joblib.load(
                MODEL_FILE
            )

            print(
                "Existing ML model loaded."
            )

        except Exception:

            print(
                "No trained model found."
            )

            self.train()

            joblib.dump(
                self.model,
                MODEL_FILE
            )

            print(
                "ML model saved."
            )

        return self.model

    def predict(self, features):

        model_input = pd.DataFrame(
            [[
                features[column]
                for column in FEATURE_COLUMNS
            ]],
            columns=FEATURE_COLUMNS
        )

        prediction = self.model.predict(
            model_input
        )[0]

        probabilities = (
            self.model.predict_proba(
                model_input
            )[0]
        )

        probabilities = dict(
            zip(
                self.model.classes_,
                probabilities
            )
        )

        return prediction, probabilities


# =========================================================
# RECOMMENDATION ENGINE
# =========================================================

class PasswordRecommendationEngine:

    def __init__(self):

        self.ml = PasswordMLModel()

        self.ml.load_or_train()

    # -----------------------------------------------------
    # SCORE
    # -----------------------------------------------------

    def calculate_score(
        self,
        features,
        probabilities
    ):

        weak = probabilities.get(
            "Weak",
            0
        )

        medium = probabilities.get(
            "Medium",
            0
        )

        strong = probabilities.get(
            "Strong",
            0
        )

        score = (
            strong * 100
            + medium * 60
            + weak * 15
        )

        # Length
        if features["length"] >= 16:
            score += 8

        elif features["length"] >= 12:
            score += 4

        elif features["length"] < 8:
            score -= 15

        # Diversity
        if features[
            "unique_character_ratio"
        ] >= 0.75:

            score += 5

        elif features[
            "unique_character_ratio"
        ] < 0.40:

            score -= 8

        # Repetition
        if features[
            "repetition_ratio"
        ] > 0.40:

            score -= 15

        elif features[
            "repetition_ratio"
        ] > 0.20:

            score -= 8

        # Predictability
        if features[
            "sequential_pattern"
        ]:

            score -= 15

        if features[
            "keyboard_pattern"
        ]:

            score -= 15

        if features[
            "common_password"
        ]:

            score -= 30

        if features[
            "dictionary_word"
        ]:

            score -= 20

        if features[
            "substitution_pattern"
        ]:

            score -= 15

        if features[
            "year_pattern"
        ]:

            score -= 8

        # Entropy
        if features[
            "entropy"
        ] >= 70:

            score += 5

        elif features[
            "entropy"
        ] < 35:

            score -= 10

        return max(
            0,
            min(
                100,
                round(score)
            )
        )

    # -----------------------------------------------------
    # RISK ANALYSIS
    # -----------------------------------------------------

    def identify_risks(
        self,
        features
    ):

        risks = []

        if features["length"] < 12:

            risks.append({
                "factor":
                    "Password is too short",
                "severity":
                    "HIGH"
            })

        if features[
            "common_password"
        ]:

            risks.append({
                "factor":
                    "Common password detected",
                "severity":
                    "CRITICAL"
            })

        if features[
            "dictionary_word"
        ]:

            risks.append({
                "factor":
                    "Dictionary word detected",
                "severity":
                    "HIGH"
            })

        if features[
            "sequential_pattern"
        ]:

            risks.append({
                "factor":
                    "Sequential pattern detected",
                "severity":
                    "HIGH"
            })

        if features[
            "keyboard_pattern"
        ]:

            risks.append({
                "factor":
                    "Keyboard pattern detected",
                "severity":
                    "HIGH"
            })

        if features[
            "substitution_pattern"
        ]:

            risks.append({
                "factor":
                    "Predictable substitution detected",
                "severity":
                    "HIGH"
            })

        if features[
            "year_pattern"
        ]:

            risks.append({
                "factor":
                    "Year pattern detected",
                "severity":
                    "MEDIUM"
            })

        if features[
            "repetition_ratio"
        ] > 0.20:

            risks.append({
                "factor":
                    "High character repetition",
                "severity":
                    "HIGH"
            })

        if features[
            "entropy"
        ] < 40:

            risks.append({
                "factor":
                    "Low estimated entropy",
                "severity":
                    "HIGH"
            })

        return risks

    # -----------------------------------------------------
    # RECOMMENDATIONS
    # -----------------------------------------------------

    def generate_recommendations(
        self,
        features
    ):

        recommendations = []

        if features["length"] < 12:

            recommendations.append({
                "message":
                    "Increase the password length to at least 12 characters.",
                "category":
                    "Length",
                "priority":
                    "HIGH",
                "impact":
                    20
            })

        elif features["length"] < 16:

            recommendations.append({
                "message":
                    "Consider using 16 or more characters.",
                "category":
                    "Length",
                "priority":
                    "MEDIUM",
                "impact":
                    10
            })

        if features[
            "common_password"
        ]:

            recommendations.append({
                "message":
                    "Avoid common passwords and frequently used password patterns.",
                "category":
                    "Predictability",
                "priority":
                    "CRITICAL",
                "impact":
                    30
            })

        if features[
            "dictionary_word"
        ]:

            recommendations.append({
                "message":
                    "Avoid using common dictionary words as the main password structure.",
                "category":
                    "Dictionary",
                "priority":
                    "HIGH",
                "impact":
                    20
            })

        if features[
            "sequential_pattern"
        ]:

            recommendations.append({
                "message":
                    "Avoid sequential patterns such as 123 or abc.",
                "category":
                    "Pattern",
                "priority":
                    "HIGH",
                "impact":
                    18
            })

        if features[
            "keyboard_pattern"
        ]:

            recommendations.append({
                "message":
                    "Avoid predictable keyboard patterns such as qwerty or asdf.",
                "category":
                    "Pattern",
                "priority":
                    "HIGH",
                "impact":
                    18
            })

        if features[
            "substitution_pattern"
        ]:

            recommendations.append({
                "message":
                    "Do not rely on predictable substitutions such as @ for a or 0 for o.",
                "category":
                    "Predictability",
                "priority":
                    "HIGH",
                "impact":
                    17
            })

        if features[
            "year_pattern"
        ]:

            recommendations.append({
                "message":
                    "Avoid predictable years or dates in the password.",
                "category":
                    "Predictability",
                "priority":
                    "MEDIUM",
                "impact":
                    10
            })

        if features[
            "special_count"
        ] == 0:

            recommendations.append({
                "message":
                    "Consider adding special characters.",
                "category":
                    "Complexity",
                "priority":
                    "MEDIUM",
                "impact":
                    8
            })

        if features[
            "digit_count"
        ] == 0:

            recommendations.append({
                "message":
                    "Consider adding numbers in a non-predictable position.",
                "category":
                    "Complexity",
                "priority":
                    "MEDIUM",
                "impact":
                    7
            })

        if features[
            "repetition_ratio"
        ] > 0.20:

            recommendations.append({
                "message":
                    "Reduce repeated characters or repeated sequences.",
                "category":
                    "Repetition",
                "priority":
                    "HIGH",
                "impact":
                    15
            })

        if features[
            "entropy"
        ] < 40:

            recommendations.append({
                "message":
                    "Use a longer and less predictable password structure.",
                "category":
                    "Entropy",
                "priority":
                    "HIGH",
                "impact":
                    20
            })

        if not recommendations:

            recommendations.append({
                "message":
                    "Password meets the current security criteria. Avoid reusing it across accounts.",
                "category":
                    "Maintenance",
                "priority":
                    "LOW",
                "impact":
                    0
            })

        recommendations.sort(
            key=lambda item:
                item["impact"],
            reverse=True
        )

        return recommendations[:5]

    # -----------------------------------------------------
    # FINAL ANALYSIS
    # -----------------------------------------------------

    def analyze(self, password):

        features = extract_features(
            password
        )

        prediction, probabilities = (
            self.ml.predict(features)
        )

        score = self.calculate_score(
            features,
            probabilities
        )

        risks = self.identify_risks(
            features
        )

        recommendations = (
            self.generate_recommendations(
                features
            )
        )

        confidence = max(
            probabilities.values()
        ) * 100

        # Final rule-based safety override.
        # This prevents a complex-looking password
        # with obvious critical patterns from being
        # reported as Strong.

        critical_risk = (
            features["common_password"]
            or
            features["keyboard_pattern"]
            or
            (
                features["dictionary_word"]
                and
                features["sequential_pattern"]
            )
        )

        if critical_risk:

            final_strength = "Weak"

        elif score >= 75:

            final_strength = "Strong"

        elif score >= 45:

            final_strength = "Medium"

        else:

            final_strength = "Weak"

        if final_strength == "Strong":

            risk_level = "LOW"

        elif final_strength == "Medium":

            risk_level = "MEDIUM"

        else:

            risk_level = "HIGH"

        return {

            "strength":
                final_strength,

            "score":
                score,

            "risk_level":
                risk_level,

            "confidence":
                round(
                    confidence,
                    2
                ),

            "ml_prediction":
                prediction,

            "probabilities": {
                key:
                    round(
                        value * 100,
                        2
                    )
                for key, value
                in probabilities.items()
            },

            "risk_factors":
                risks,

            "recommendations":
                recommendations,

            "features":
                features,
        }


# =========================================================
# SINGLE ENGINE INSTANCE
# =========================================================

engine = PasswordRecommendationEngine()


# =========================================================
# SIMPLE FUNCTION FOR API
# =========================================================

def analyze_password(password):

    return engine.analyze(
        password
    )