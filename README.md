# Hybrid Intrusion Detection System (IDS)

A machine-learning based **Intrusion Detection System (IDS)** that analyzes network-flow features to detect malicious traffic, classify the detected attack type, identify possible attack-chain patterns, and generate risk-based alerts.

The project combines:

- **Random Forest / XGBoost** for attack classification
- **Association-rule based attack-chain analysis** for identifying possible relationships between attacks
- **NetworkX** for attack-topology visualization
- A lightweight **stream-processing simulation** to demonstrate repeated incoming traffic detection and alert generation

> **Scope:** This project is an **intrusion detection and alerting system**. It detects suspicious traffic and provides contextual alerts; it does **not automatically block, patch, isolate, or remediate an attack**.

---

## 1. Project Overview

The system is designed around the following security workflow:

```text
Incoming Network Traffic
          │
          ▼
   Feature Extraction
          │
          ▼
 ┌───────────────────────┐
 │ Normal / Attack Gate  │
 │   (logical stage)     │
 └──────────┬────────────┘
            │
      ┌─────┴─────┐
      │           │
    Normal      Attack
      │           │
      │           ▼
      │    Attack Classification
      │     RF / XGBoost / DT
      │           │
      │           ▼
      │    Attack-Type Mapping
      │           │
      │           ▼
      │  Attack-Chain Analysis
      │  confidence + lift rules
      │           │
      │           ▼
      │     Risk Calculation
      │           │
      │           ▼
      │      Alert Generation
      │           │
      │           ▼
      │   NetworkX Attack Graph
      │
      ▼
   Ignore / benign flow
```

### Important implementation note

The **current notebook does not train a separate binary `BENIGN vs ATTACK` classifier**. During preprocessing, benign traffic is removed and the remaining attack traffic is classified into five attack categories.

Therefore, the normal/attack gate shown above represents the **intended IDS architecture**, while the implemented notebook starts from attack traffic and performs **multiclass attack classification**.

Similarly, the notebook's current attack-chain stage uses a manually defined association-rule table. It **does not currently run an FP-Growth implementation over the dataset**. The rules are consumed using `confidence` and `lift`; `support` is not calculated in the current code.

---

## 2. Key Features

### Machine Learning Attack Detection

The notebook evaluates multiple classifiers:

- Decision Tree
- Random Forest
- XGBoost

The final multiclass task predicts one of:

- `DDoS`
- `DoS Hulk`
- `DoS Slowhttptest`
- `DoS slowloris`
- `FTP-Patator`

### Class Imbalance Handling

The dataset is highly imbalanced, especially because `DoS Hulk` contains far more samples than the other selected classes.

The training split is therefore balanced through **random undersampling**:

```text
Largest class
     │
     ▼
Match every class to the smallest training-class size
     │
     ▼
Balanced training set
```

Each of the five classes is reduced to **4,182 training samples**.

The original test set is kept intact, so model performance is evaluated on the naturally distributed test data.

### Attack-Chain Pattern Analysis

After an attack type is predicted, the system looks for a matching relationship in an association-rule table such as:

```text
Malware → DDoS
SQL Injection → XSS Attack
Ransomware → Privilege Escalation
Port Scanning → Brute Force
Privilege Escalation → DDoS
```

The current rule engine considers:

- **Confidence** — how strongly the rule connects the source and target attack in the supplied rule table
- **Lift** — the strength of the association relative to baseline occurrence

The system checks both directions:

```text
Current attack → possible next attack
```

and

```text
Possible previous attack → current attack
```

This enables the alerting layer to provide contextual information about a possible multi-step attack sequence.

### Risk-Based Alerts

A rule is converted into a risk score using:

```text
Risk Score =
    confidence × 50
  + lift × 20
  + severity(next attack) × 10
```

The project then classifies the alert as:

```text
Risk > 80  → CRITICAL
Risk > 60  → HIGH
Otherwise  → MEDIUM
```

> These thresholds and weights are project-defined heuristic rules, not standardized cybersecurity severity levels.

### Attack Topology Visualization

`NetworkX` is used to build a directed graph:

```text
Attack A ───────► Attack B
   │                 │
   └────► Attack C ◄─┘
```

- Nodes represent attack types.
- Directed edges represent possible attack transitions.
- Edge labels represent rule confidence.
- The currently detected attack is highlighted.

### Stream / Real-Time Demonstration

The notebook simulates incoming traffic by repeatedly taking samples from the test set:

```text
Traffic #1 → Predict → Map → Alert → Visualize
Traffic #2 → Predict → Map → Alert → Visualize
Traffic #3 → Predict → Map → Alert → Visualize
...
```

A short delay is added between events to give the output a streaming / real-time monitoring feel.

> This is a **simulation using stored test samples**, not a live packet-capture or live socket-based IDS deployment.

---

## 3. Dataset

The notebook uses network-flow data from the **CICIDS2017** dataset.

The raw CSV files are merged before preprocessing.

Initial combined dataset:

```text
Rows:    1,223,054
Columns: 79
```

The dataset contains flow-level network features such as:

- Destination Port
- Flow Duration
- Forward / backward packet counts
- Forward / backward packet lengths
- Flow bytes and packets per second
- Flow inter-arrival times
- TCP flag counts
- Header lengths
- Packet-length statistics
- Active / idle time statistics
- Attack label

---

## 4. Data Preprocessing

### Step 1 — Merge CSV files

All CSV files available under the input directory are loaded with Pandas and concatenated.

```python
files = glob.glob("/content/*.csv")
data = pd.concat(df_list, ignore_index=True)
```

The merged file is also exported as:

```text
cicids2017_cleaned.csv
```

### Step 2 — Clean column names

Whitespace is removed from column names:

```python
data.columns = data.columns.str.strip()
```

### Step 3 — Clean attack labels

The notebook normalizes malformed web-attack label text.

### Step 4 — Remove benign traffic

```python
data = data[~data['Label'].str.upper().str.contains('BENIGN')]
```

The cleaned attack distribution before selecting the top five classes is:

| Attack Type | Samples |
|---|---:|
| DoS Hulk | 115,987 |
| DDoS | 15,471 |
| FTP-Patator | 5,931 |
| DoS slowloris | 5,385 |
| DoS Slowhttptest | 5,228 |
| SSH-Patator | 1,685 |
| Web Attack Brute Force | 687 |
| PortScan | 102 |
| Bot | 2 |

### Step 5 — Keep the five most frequent attack classes

The notebook keeps:

```text
DoS Hulk
DDoS
FTP-Patator
DoS slowloris
DoS Slowhttptest
```

### Step 6 — Handle invalid values

Infinite values are converted to `NaN`, and missing feature values are filled using column medians.

### Step 7 — Remove duplicates

Duplicate rows are removed before model training.

### Step 8 — Remove leakage-prone / identifier columns

When present, the following columns are dropped:

```text
Flow ID
Src IP
Source IP
Dst IP
Destination IP
Timestamp
```

The feature matrix is then restricted to numeric columns.

### Step 9 — Encode labels

`LabelEncoder` converts the five attack names into numeric class IDs.

### Step 10 — Stratified train-test split

```python
train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)
```

This preserves the relative class distribution in the test split.

### Step 11 — Balance only the training data

The training set is undersampled so that every attack class contains the same number of samples.

```text
DDoS              → 4,182
DoS Hulk          → 4,182
DoS Slowhttptest  → 4,182
DoS slowloris     → 4,182
FTP-Patator       → 4,182
```

The **test set is not undersampled**, allowing evaluation on the original class distribution.

---

## 5. Machine Learning Models

The notebook compares three multiclass classifiers.

### Decision Tree

```python
DecisionTreeClassifier(
    max_depth=10,
    random_state=42
)
```

### Random Forest

```python
RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1
)
```

Random Forest also provides feature-importance values used to visualize the top contributing network-flow features.

### XGBoost

```python
XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="mlogloss",
    random_state=42
)
```

---

## 6. Model Performance

The notebook reports the following results on the held-out test set:

| Model | Accuracy | Macro F1 |
|---|---:|---:|
| Decision Tree | 99.9155% | 99.5965% |
| Random Forest | **99.9527%** | **99.7528%** |
| XGBoost | 99.9358% | 99.7182% |

### Random Forest classification performance

The reported Random Forest metrics are approximately:

| Attack Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| DDoS | 1.00 | 1.00 | 1.00 |
| DoS Hulk | 1.00 | 1.00 | 1.00 |
| DoS Slowhttptest | 1.00 | 0.99 | 0.99 |
| DoS slowloris | 0.99 | 1.00 | 0.99 |
| FTP-Patator | 1.00 | 1.00 | 1.00 |

Random Forest is therefore used as the main prediction model in the later demonstration cells.

---

## 7. Hybrid IDS Pipeline

The core hybrid workflow is:

```text
Network Flow Features
        │
        ▼
Preprocessing
        │
        ▼
Random Forest / XGBoost
        │
        ▼
Predicted Attack Type
        │
        ▼
Attack Label Mapping
        │
        ▼
Association Rules
        │
        ├──► Previous Attack
        │
        └──► Next Likely Attack
        │
        ▼
Confidence + Lift
        │
        ▼
Risk Score
        │
        ▼
Alert Level
        │
        ▼
NetworkX Attack Graph
```

The hybrid idea is useful because the classifier answers:

> **“What attack does this network flow most closely resemble?”**

while the rule layer answers:

> **“What attack pattern may be associated with this attack?”**

---

## 8. Attack Label Mapping

The notebook maps some detailed dataset labels into broader security categories for attack-chain analysis.

Current mapping includes:

```python
{
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "PortScan": "Port Scanning",
    "DoS Hulk": "DDoS",
    "DoS GoldenEye": "DDoS",
    "DDoS": "DDoS"
}
```

For example:

```text
Model prediction:
DoS Hulk

        ↓ mapping

Normalized attack:
DDoS
```

This makes the attack-chain graph use higher-level attack categories rather than keeping every dataset label separate.

---

## 9. Attack-Chain Rule Engine

The notebook contains a set of predefined association rules.

Example:

```python
{
    "from": "Malware",
    "to": "DDoS",
    "confidence": 0.3333,
    "lift": 1.23
}
```

The rule engine searches for:

### Forward relationship

```text
Current Attack → Next Likely Attack
```

### Backward relationship

```text
Previous Attack → Current Attack
```

For a predicted attack, the rule with the highest:

```text
confidence × lift
```

is selected.

Example output:

```text
ML Prediction: DDoS

Pattern: Previous → Current Attack
Malware → DDoS

Possible Previous Attack: Malware

Confidence: 0.333
Lift: 1.23
Risk Score: 91.27

ALERT: CRITICAL
```

This indicates that the system can associate a detected attack with a possible preceding or subsequent stage in an attack chain.

---

## 10. FP-Growth / Association Analysis Note

The project concept uses **frequent-pattern / association-rule analysis** to discover relationships between attack types.

However, the current notebook implementation does **not** contain a direct call to an FP-Growth algorithm such as:

```python
fpgrowth(...)
```

or a frequent-itemset generation pipeline.

Instead, the notebook currently provides the resulting rules manually:

```python
association_rules = [
    ...
]
```

and uses their `confidence` and `lift` values for alert generation and graph construction.

### Current implementation

```text
Predefined association rules
        │
        ▼
Confidence + Lift
        │
        ▼
Rule matching
        │
        ▼
Risk score + alert
```

### Full FP-Growth implementation that could be added later

A production/research version could instead:

```text
Attack-event transactions
        │
        ▼
Frequent itemset mining
        │
        ▼
FP-Growth
        │
        ▼
Association rules
        │
        ├── Support
        ├── Confidence
        └── Lift
        │
        ▼
Attack-chain inference
```

This would make the attack-chain relationships data-derived rather than manually specified.

---

## 11. Risk and Alert Engine

Each supported attack has a project-defined severity value.

Example categories include:

```text
Port Scanning        → 2
Brute Force          → 3
XSS Attack            → 3
SQL Injection         → 4
Malware               → 4
MITM Attack           → 4
DDoS                  → 5
Privilege Escalation  → 5
Ransomware            → 5
Botnet                → 5
```

The risk formula combines:

- association confidence
- lift
- target attack severity

```text
Risk =
confidence × 50
+ lift × 20
+ severity × 10
```

Then:

```text
> 80  → CRITICAL
> 60  → HIGH
≤ 60  → MEDIUM
```

This provides an additional context layer on top of raw ML classification.

---

## 12. NetworkX Attack Graph

The attack rules are represented as a directed graph:

```text
           ┌──────────────┐
           │    Malware   │
           └──────┬───────┘
                  │
                  ▼
           ┌──────────────┐
           │     DDoS     │
           └──────┬───────┘
                  │
              possible
              next step
                  │
                  ▼
              ...
```

The graph:

- uses a directed edge for each attack rule
- stores confidence as the edge weight
- labels edges with confidence
- highlights the currently detected attack

The notebook also provides a local graph function that can display the current attack together with its direct predecessors and successors.

---

## 13. Simulated Real-Time Detection

The notebook demonstrates repeated event processing using samples from `X_test`.

For each incoming event:

```text
1. Take network-flow feature vector
2. Run Random Forest prediction
3. Decode the predicted class
4. Map the class to a normalized attack category
5. Search association rules
6. Compute risk
7. Generate alert
8. Display attack graph
```

The notebook runs five demo events with a two-second delay between them.

Example:

```text
==============================
Incoming Traffic #0

Original Prediction: DoS Hulk
Mapped Attack: DDoS

===== HYBRID IDS OUTPUT =====
Pattern: Previous → Current Attack
Malware → DDoS

Confidence: 0.333
Lift: 1.23
Risk Score: 91.27

ALERT: CRITICAL
```

Again, this is a **simulation over stored test records** rather than live network capture.

---

## 14. Visualizations

The notebook produces several security-oriented visualizations:

### Class Distribution

Shows the balanced training data after undersampling.

### Confusion Matrices

Generated for:

- Decision Tree
- Random Forest
- XGBoost

### Feature Importance

Random Forest feature importance is used to identify the most influential network-flow features.

### Attack Chain Graph

NetworkX displays:

- attack nodes
- directional attack relationships
- confidence values
- highlighted current attack

---

## 15. Tech Stack

### Programming Language

- Python

### Data Processing

- Pandas
- NumPy

### Machine Learning

- Scikit-learn
- XGBoost

### Visualization

- Matplotlib
- Seaborn
- NetworkX

### Dataset

- CICIDS2017

### Main ML Concepts

- Multiclass classification
- Random Forest
- Decision Tree
- Gradient-boosted trees / XGBoost
- Train-test split
- Stratification
- Random undersampling
- Label encoding
- Feature importance
- Confusion matrix
- Precision / Recall / F1
- Association rules
- Confidence
- Lift
- Risk scoring

---

## 16. Project Structure

The current project is notebook-based:

```text
Hybrid-Intrusion-Detection-System/
│
├── IDS.ipynb
└── README.md
```

During notebook execution, the merged dataset is generated as:

```text
cicids2017_cleaned.csv
```

> The CICIDS2017 source CSV files are not assumed to be part of this repository. They need to be supplied separately before running the notebook.

---

## 17. How to Run

### Option 1 — Google Colab

1. Open `IDS.ipynb` in Google Colab.
2. Upload the required CICIDS2017 CSV files.
3. Place the CSV files where the notebook can access `/content/*.csv`.
4. Run the notebook cells in order.
5. Review:
   - preprocessing
   - class balancing
   - model training
   - evaluation
   - association-rule alerting
   - NetworkX visualization
   - stream simulation

### Option 2 — Local Jupyter Environment

Install the main dependencies:

```bash
pip install pandas numpy scikit-learn xgboost matplotlib seaborn networkx jupyter
```

Then launch:

```bash
jupyter notebook
```

Open:

```text
IDS.ipynb
```

and provide the CICIDS2017 CSV files.

---

## 18. What This Project Detects

The current trained model focuses on five attack classes:

```text
DDoS
DoS Hulk
DoS Slowhttptest
DoS slowloris
FTP-Patator
```

The broader rule/visualization layer also contains higher-level concepts such as:

```text
Malware
Brute Force
Port Scanning
SQL Injection
XSS Attack
MITM Attack
Privilege Escalation
Ransomware
Botnet
```

These broader categories are currently used in the predefined association-rule and graph layer; they are not all trained as direct multiclass outputs of the notebook's final ML model.

---

## 19. Limitations

This project is intentionally a detection-focused prototype. Important limitations of the current notebook are:

### No automatic response

The system does not automatically:

- block an IP
- terminate a session
- quarantine a host
- modify firewall rules
- patch a vulnerable service
- remove malware

The displayed recommendation is for investigation / isolation by an operator.

### Binary benign-vs-attack model is not trained

Benign traffic is removed before multiclass training.

A complete deployed IDS would typically need an explicit first-stage detector or another mechanism to distinguish:

```text
BENIGN ↔ ATTACK
```

before classifying the attack type.

### FP-Growth is not executed in the current notebook

The current attack-chain rules are predefined manually.

### Support is not currently calculated

The rule engine uses `confidence` and `lift`. A true FP-Growth pipeline should calculate frequent-itemset support as well.

### Simulated streaming

The “real-time” section uses historical test rows with a delay. It is not connected to:

- live packet capture
- NetFlow
- Zeek
- Suricata
- raw sockets
- Kafka / message queues

### Dataset dependence

The very high benchmark scores are obtained on the selected CICIDS2017 setup and should not be interpreted as equivalent performance on unseen production traffic.

---

## 20. Possible Future Improvements

A more production-oriented version could extend the project with:

### True two-stage IDS

```text
Stage 1:
BENIGN vs ATTACK

Stage 2:
Attack Type Classification
```

### Real FP-Growth Pipeline

Automatically derive attack chains from historical attack-event transactions:

```text
Raw attack events
      ↓
Transactions
      ↓
FP-Growth
      ↓
Frequent itemsets
      ↓
Association rules
      ↓
Support / Confidence / Lift
      ↓
Attack-chain prediction
```

### Live Traffic Integration

Connect the classifier to:

- packet capture
- NetFlow
- Zeek
- Suricata
- Kafka / streaming infrastructure

### Persistent Alert Storage

Store alerts in:

- PostgreSQL
- MongoDB
- Elasticsearch
- a security-event platform

### Monitoring Dashboard

Expose:

- current attack
- severity
- attack history
- attack-chain graph
- confidence
- risk score
- top attack sources

### Better Evaluation

Add:

- cross-validation
- precision-recall curves
- ROC-AUC where applicable
- per-class error analysis
- external/unseen dataset evaluation
- latency and throughput measurements

---

## 21. Project Takeaway

This project demonstrates a **hybrid intrusion-detection workflow** where machine learning performs attack classification and a rule/graph layer adds contextual interpretation.

The key idea is:

```text
ML Classification
       +
Attack-Pattern Analysis
       +
Risk-Based Alerting
       +
Graph Visualization
       =
Hybrid IDS
```

The machine-learning model identifies **what kind of attack is present**, while the attack-pattern layer helps answer **how that attack may relate to other stages of a larger attack sequence**.

The system is designed for **detection, contextualization, visualization, and alerting**, not automated attack resolution.
