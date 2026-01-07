# Model Hyperparameters Explained

This document explains the FLAML-optimized hyperparameters for all trained EPSS prediction models, including what each parameter does and how changing values affects model behavior.

---

## 🌲 Random Forest

**FLAML-Optimized Configuration:**

```json
{
  "n_estimators": 66,
  "max_depth": "unlimited",
  "min_samples_split": 2,
  "min_samples_leaf": 1,
  "max_features": 0.47,
  "random_state": 12032022
}
```

### Parameters Explained

#### `n_estimators: 66`

**What it is:** Number of decision trees in the forest

**FLAML chose:** 66 trees

**Impact of changing:**

- **Increase (e.g., 100, 200):**
  - ✅ More stable predictions (reduces variance)
  - ✅ Better generalization
  - ❌ Slower training and prediction
  - ❌ Diminishing returns after certain point
- **Decrease (e.g., 20, 30):**
  - ✅ Faster training/prediction
  - ❌ More unstable predictions
  - ❌ Higher variance, lower accuracy

---

#### `max_depth: unlimited`

**What it is:** Maximum depth of each tree (unlimited = grow until pure leaves)

**FLAML chose:** No limit (trees grow until all leaves are pure)

**Impact of changing:**

- **Set limit (e.g., 10, 20):**
  - ✅ Prevents overfitting
  - ✅ Faster training
  - ✅ Less memory usage
  - ❌ Might underfit if too shallow
- **Unlimited (None):**
  - ✅ Can capture complex patterns
  - ❌ Risk of overfitting
  - ❌ Slower training

**Example:** `max_depth=5` creates simple trees good for noisy data. `max_depth=None` creates deep trees that memorize training patterns.

---

#### `min_samples_split: 2`

**What it is:** Minimum samples required to split an internal node

**FLAML chose:** 2 (default - most aggressive splitting)

**Impact of changing:**

- **Increase (e.g., 10, 50):**
  - ✅ Prevents overfitting (creates simpler trees)
  - ✅ Faster training
  - ❌ Might miss fine-grained patterns
- **Decrease (stay at 2):**
  - ✅ Captures detailed patterns
  - ❌ More prone to overfitting

**Example:** With `min_samples_split=50`, nodes with <50 samples won't split, creating broader generalizations. With 2, trees split aggressively.

---

#### `min_samples_leaf: 1`

**What it is:** Minimum samples required in a leaf node

**FLAML chose:** 1 (allows single-sample leaves)

**Impact of changing:**

- **Increase (e.g., 5, 10):**
  - ✅ Smoother decision boundaries
  - ✅ Better generalization
  - ❌ Might miss rare patterns
- **Keep at 1:**
  - ✅ Can learn rare patterns
  - ❌ More sensitive to outliers

**Example:** `min_samples_leaf=5` forces each prediction to be based on at least 5 samples. With 1, the model can create rules for single outliers.

---

#### `max_features: 0.47`

**What it is:** Fraction of features to consider when looking for best split

**FLAML chose:** 47% of features (~15 out of 33)

**Impact of changing:**

- **Increase (e.g., 0.7, 1.0):**
  - ✅ Trees consider more information
  - ❌ Less diversity between trees
  - ❌ Higher correlation, less ensemble benefit
- **Decrease (e.g., 0.3, 0.2):**
  - ✅ More diverse trees
  - ✅ Better ensemble effect
  - ❌ Each tree has less information

**Example:** `max_features=1.0` makes all trees similar. `max_features=0.3` creates diverse trees that vote differently, improving ensemble predictions.

---

#### `random_state: 12032022`

**What it is:** Seed for random number generator (ensures reproducibility)

**FLAML chose:** 12032022 (date-based seed)

**Impact:** Controls randomness in bootstrap sampling and feature selection. Same seed = same model every time.

---

## 🚀 XGBoost

**FLAML-Optimized Configuration:**

```json
{
  "n_estimators": 159,
  "max_depth": 0,
  "learning_rate": 0.026,
  "subsample": 0.914,
  "colsample_bytree": 0.861,
  "reg_alpha": 0.191,
  "reg_lambda": 10.456
}
```

### Parameters Explained

#### `n_estimators: 159`

**What it is:** Number of boosting rounds (sequential trees)

**FLAML chose:** 159 rounds

**Impact of changing:**

- **Increase (e.g., 300, 500):**
  - ✅ Better training accuracy
  - ❌ Risk of overfitting
  - ❌ Slower training
- **Decrease (e.g., 50, 100):**
  - ✅ Faster training
  - ❌ Might underfit

**Example:** With 50 trees, the model stops learning early. With 500 trees and low learning rate, it might overfit to training noise.

---

#### `max_depth: 0`

**What it is:** Maximum depth of each tree (0 = unlimited in XGBoost)

**FLAML chose:** Unlimited depth

**Impact of changing:**

- **Set limit (e.g., 3, 6):**
  - ✅ Prevents overfitting
  - ✅ Faster training
  - ❌ Less expressive trees
- **Unlimited (0):**
  - ✅ Complex interactions
  - ❌ Overfitting risk

**Example:** `max_depth=3` creates simple trees (good for linear patterns). `max_depth=0` captures complex non-linear interactions.

---

#### `learning_rate: 0.026`

**What it is:** Step size shrinkage to prevent overfitting (also called eta)

**FLAML chose:** Very conservative 0.026 (2.6%)

**Impact of changing:**

- **Increase (e.g., 0.1, 0.3):**
  - ✅ Faster convergence
  - ✅ Fewer trees needed
  - ❌ Might overshoot optimal solution
  - ❌ Higher overfitting risk
- **Decrease (e.g., 0.01):**
  - ✅ More precise optimization
  - ✅ Better generalization
  - ❌ Need more trees (slower)

**Example:** With `learning_rate=0.3`, model learns fast but might miss subtle patterns. With 0.01, it learns slowly but precisely.

---

#### `subsample: 0.914`

**What it is:** Fraction of training samples used for each tree

**FLAML chose:** Use 91.4% of data per tree

**Impact of changing:**

- **Increase (closer to 1.0):**
  - ✅ More data per tree
  - ❌ Less diversity, more overfitting
- **Decrease (e.g., 0.5, 0.7):**
  - ✅ Better generalization
  - ✅ Faster training
  - ❌ Higher variance per tree

**Example:** `subsample=0.5` trains each tree on random 50% of data (like bagging). `subsample=1.0` uses all data (less stochastic).

---

#### `colsample_bytree: 0.861`

**What it is:** Fraction of features used for each tree

**FLAML chose:** Use 86% of features per tree

**Impact of changing:**

- **Increase (closer to 1.0):**
  - ✅ Trees have more information
  - ❌ Less diverse ensemble
- **Decrease (e.g., 0.5, 0.7):**
  - ✅ More diverse trees
  - ✅ Prevents overfitting
  - ❌ Less information per tree

**Example:** `colsample_bytree=0.5` randomly picks half the features for each tree, creating diverse trees. `colsample_bytree=1.0` uses all features.

---

#### `reg_alpha: 0.191` (L1 Regularization)

**What it is:** L1 penalty on leaf weights (promotes sparsity)

**FLAML chose:** Light L1 regularization

**Impact of changing:**

- **Increase (e.g., 1.0, 10.0):**
  - ✅ More feature selection (sparsity)
  - ✅ Prevents overfitting
  - ❌ Might eliminate useful features
- **Decrease (close to 0):**
  - ✅ Uses all features
  - ❌ Less regularization

**Example:** High `reg_alpha=10` forces model to use fewer features. Low value uses all available features.

---

#### `reg_lambda: 10.456` (L2 Regularization)

**What it is:** L2 penalty on leaf weights (smooths weights)

**FLAML chose:** Strong L2 regularization (10.456)

**Impact of changing:**

- **Increase (e.g., 50, 100):**
  - ✅ Smoother predictions
  - ✅ Prevents overfitting
  - ❌ Might underfit
- **Decrease (e.g., 0, 1):**
  - ✅ More expressive model
  - ❌ Higher overfitting risk

**Example:** High `reg_lambda=50` creates conservative predictions close to mean. Low value allows extreme predictions.

---

## 💡 LightGBM

**FLAML-Optimized Configuration:**

```json
{
  "n_estimators": 1527,
  "max_depth": -1,
  "learning_rate": 0.02,
  "num_leaves": 57,
  "subsample": 1.0,
  "colsample_bytree": 0.513,
  "reg_alpha": 0.001,
  "reg_lambda": 0.469
}
```

### Parameters Explained

#### `n_estimators: 1527`

**What it is:** Number of boosting iterations

**FLAML chose:** Very large ensemble (1527 trees!)

**Impact of changing:**

- **Increase (e.g., 2000+):**
  - ✅ Better training fit
  - ❌ Overfitting risk
  - ❌ Slower training/inference
- **Decrease (e.g., 500, 1000):**
  - ✅ Faster training
  - ❌ Might underfit

**Note:** LightGBM chose many trees because learning rate is very low (0.02), requiring more iterations to converge.

---

#### `max_depth: -1`

**What it is:** Maximum tree depth (-1 = unlimited)

**FLAML chose:** Unlimited depth (controlled by `num_leaves` instead)

**Impact of changing:**

- **Set limit (e.g., 5, 10):**
  - ✅ Controls complexity
  - ✅ Faster training
  - ❌ Might miss complex patterns
- **Unlimited (-1):**
  - ✅ Flexibility (controlled by num_leaves)
  - ❌ Need other constraints

**Note:** LightGBM uses leaf-wise growth, so `num_leaves` is more important than `max_depth`.

---

#### `learning_rate: 0.020`

**What it is:** Shrinkage rate for boosting

**FLAML chose:** Very conservative 0.02 (2%)

**Impact of changing:**

- **Increase (e.g., 0.1):**
  - ✅ Faster convergence
  - ✅ Fewer trees needed
  - ❌ Risk overshooting
- **Decrease (e.g., 0.01):**
  - ✅ More precise
  - ❌ Need even more trees

**Example:** Low learning rate + many trees = slow, precise learning. High learning rate + few trees = fast, approximate learning.

---

#### `num_leaves: 57`

**What it is:** Maximum number of leaves per tree

**FLAML chose:** 57 leaves (moderately complex trees)

**Impact of changing:**

- **Increase (e.g., 100, 200):**
  - ✅ More expressive trees
  - ❌ Overfitting risk
  - ❌ Slower training
- **Decrease (e.g., 15, 31):**
  - ✅ Simpler trees
  - ✅ Better generalization
  - ❌ Might underfit

**Example:** `num_leaves=15` creates simple trees. `num_leaves=200` creates very complex trees that might overfit.

**Key relationship:** Typically `num_leaves ≤ 2^max_depth`. With 57 leaves, equivalent to depth ~6.

---

#### `subsample: 1.0`

**What it is:** Fraction of data used per tree

**FLAML chose:** Use all data (100%)

**Impact:** No row sampling, using all available training data per iteration. This works because other regularization (low learning rate, moderate num_leaves) prevents overfitting.

---

#### `colsample_bytree: 0.513`

**What it is:** Fraction of features used per tree

**FLAML chose:** ~51% of features (17 out of 33)

**Impact of changing:**

- **Increase (e.g., 0.8, 1.0):**
  - ✅ More information per tree
  - ❌ Less diversity
- **Decrease (e.g., 0.3):**
  - ✅ More diverse trees
  - ❌ Less information

**Example:** Using 51% features creates diverse trees while still having enough information for good splits.

---

#### `reg_alpha: 0.001`

**What it is:** L1 regularization penalty

**FLAML chose:** Minimal L1 regularization (almost none)

**Impact:** Allows model to use all features without forcing sparsity. Relies on other regularization methods.

---

#### `reg_lambda: 0.469`

**What it is:** L2 regularization penalty

**FLAML chose:** Moderate L2 regularization

**Impact of changing:**

- **Increase (e.g., 1.0, 10.0):**
  - ✅ Smoother predictions
  - ✅ Better generalization
- **Decrease (close to 0):**
  - ✅ More flexible
  - ❌ Overfitting risk

---

## 🔍 K-Nearest Neighbors

**FLAML-Optimized Configuration:**

```json
{
  "n_neighbors": 129,
  "weights": "distance",
  "algorithm": "auto",
  "leaf_size": 30,
  "p": 2
}
```

### Parameters Explained

#### `n_neighbors: 129`

**What it is:** Number of nearest neighbors to consider

**FLAML chose:** 129 neighbors (very smooth averaging)

**Impact of changing:**

- **Increase (e.g., 200, 500):**
  - ✅ Smoother predictions (more averaging)
  - ✅ Less sensitive to outliers
  - ❌ Might miss local patterns
  - ❌ Predictions closer to mean
- **Decrease (e.g., 5, 10):**
  - ✅ Captures local patterns
  - ✅ More responsive to details
  - ❌ Sensitive to noise
  - ❌ Higher variance

**Example:** With `k=5`, prediction is average of 5 nearest CVEs (captures local patterns but noisy). With `k=500`, very smooth but might miss specifics.

**Why 129 works:** Large dataset (31K validation samples) allows using many neighbors for stable predictions.

---

#### `weights: distance`

**What it is:** How to weight neighbor contributions

**FLAML chose:** Weight by inverse distance (closer neighbors matter more)

**Options:**

- **`distance` (chosen):**
  - ✅ Closer points have more influence
  - ✅ More precise predictions
  - Example: Neighbor at distance 0.1 has 10x more weight than one at distance 1.0
- **`uniform` (alternative):**
  - All neighbors weighted equally
  - Simpler, more stable
  - Less precise

**Example:** With `weights='distance'`, a very similar CVE (distance=0.01) dominates the prediction. With `uniform`, all 129 neighbors vote equally.

---

#### `algorithm: auto`

**What it is:** Algorithm to compute nearest neighbors

**FLAML chose:** Auto-select based on data

**Options:**

- **`auto`:** Chooses best algorithm based on data
- **`ball_tree`:** Good for high dimensions
- **`kd_tree`:** Fast for low dimensions
- **`brute`:** Exact but slow

**Impact:** Only affects speed, not accuracy. Auto-selection optimizes for your dataset size/dimensions.

---

#### `leaf_size: 30`

**What it is:** Leaf size for BallTree/KDTree (affects speed, not predictions)

**FLAML chose:** Default value (30)

**Impact of changing:**

- **Increase (e.g., 50, 100):**
  - ✅ Faster construction
  - ❌ Slower queries
- **Decrease (e.g., 10, 20):**
  - ❌ Slower construction
  - ✅ Faster queries

**Note:** This is a speed/memory tradeoff parameter, doesn't affect prediction accuracy.

---

#### `p: 2`

**What it is:** Power parameter for Minkowski distance metric

**FLAML chose:** 2 (Euclidean distance)

**Options:**

- **`p=1`:** Manhattan distance (sum of absolute differences)
- **`p=2` (chosen):** Euclidean distance (straight-line distance)
- **`p>2`:** Higher order distances

**Example:** For two CVEs with features [0.5, 0.3] and [0.7, 0.1]:

- **Euclidean (p=2):** distance = √((0.2)² + (0.2)²) = 0.283
- **Manhattan (p=1):** distance = |0.2| + |0.2| = 0.4

**Impact:** Euclidean is most common for continuous features like EPSS scores.

---

## 📊 Model Comparison Summary

### Training Strategy by Model

| Model             | Strategy                                | Key Trade-off                                   |
| ----------------- | --------------------------------------- | ----------------------------------------------- |
| **Random Forest** | Moderate trees (66), unlimited depth    | Balanced: not too many trees, deep learning     |
| **XGBoost**       | Medium trees (159), very low LR (0.026) | Precision: slow learning, strong L2 reg         |
| **LightGBM**      | Many trees (1527), tiny LR (0.020)      | Patient: very gradual learning, many iterations |
| **KNN**           | Large k (129), distance-weighted        | Smooth: heavily averaged, local precision       |

### Regularization Approaches

| Model             | Primary Regularization                                 |
| ----------------- | ------------------------------------------------------ |
| **Random Forest** | Feature sampling (47%), ensemble diversity             |
| **XGBoost**       | Strong L2 (10.5), moderate sampling                    |
| **LightGBM**      | Low learning rate + many trees, feature sampling (51%) |
| **KNN**           | Large k (129 neighbors smoothing)                      |

### Speed vs. Accuracy Trade-offs

**Fastest Prediction:** Random Forest (66 trees, parallel)  
**Slowest Prediction:** LightGBM (1527 trees, sequential)  
**Best Accuracy:** LightGBM (R² = 0.221)  
**Most Interpretable:** Random Forest (fewer trees to visualize)

---

## 🎯 Key Insights from FLAML Optimization

### Why LightGBM Won

1. **Patient learning:** 1527 trees with 0.02 learning rate = very gradual, precise optimization
2. **Balanced regularization:** Moderate L2, good feature sampling
3. **Optimal complexity:** 57 leaves per tree (sweet spot)

### Why XGBoost Was Close

1. **Strong regularization:** High L2 (10.5) prevented overfitting
2. **Conservative learning:** Low LR (0.026)
3. **Good sampling:** 91% data + 86% features

### Why Random Forest Was Competitive

1. **Efficient ensemble:** 66 trees is enough with good diversity
2. **Smart feature sampling:** 47% creates diverse trees
3. **Unlimited depth** compensated by ensemble averaging

### Why KNN Underperformed

1. **High bias:** k=129 over-smooths, loses local patterns
2. **Distance-based:** Struggles with high-dimensional spaces (33 features)
3. **No feature learning:** Uses raw scaled features without learning interactions

---

## 💡 Practical Recommendations

### If you need faster predictions:

- Use **Random Forest** (66 trees, fast parallel inference)
- Or reduce LightGBM `n_estimators` to ~500

### If you need best accuracy:

- Stick with **LightGBM** as-is
- Or try increasing XGBoost `n_estimators` to 300 with early stopping

### If you're retraining on new data:

- Keep learning rates low (0.02-0.05)
- Use high regularization (L2 > 1.0)
- Many trees + low LR > few trees + high LR

### For production deployment:

- **LightGBM** for best predictions (if speed acceptable)
- **Random Forest** for fast predictions with good accuracy
- Avoid KNN (slowest, lowest accuracy)

---

## 🔬 Advanced: Hyperparameter Relationships

### XGBoost/LightGBM: Learning Rate × N_Estimators

- **Low LR + Many trees:** Slow, precise convergence (what FLAML chose)
- **High LR + Few trees:** Fast, approximate convergence
- **Rule of thumb:** `learning_rate × n_estimators ≈ constant` for similar total learning

FLAML choices:

- XGBoost: 0.026 × 159 = 4.13
- LightGBM: 0.020 × 1527 = 30.54

LightGBM goes much deeper (7x more "total learning")!

### Tree Complexity Controls

**Random Forest:** Controlled by depth (unlimited) + feature sampling (47%)  
**XGBoost:** Controlled by L2 regularization (10.5)  
**LightGBM:** Controlled by num_leaves (57) + feature sampling (51%)

### Regularization Balance

**L1 vs L2:**

- High L1: Feature selection (XGBoost: 0.19)
- High L2: Weight smoothing (XGBoost: 10.5)
- LightGBM: Low both, relies on learning rate

---

_This analysis is based on the FLAML AutoML optimization run on 155K CVEs for EPSS score prediction. Your optimal hyperparameters may vary with different datasets._
