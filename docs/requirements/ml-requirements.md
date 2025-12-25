# Machine Learning Requirements

**Document Owner**: ML Engineering Team + Detection Engineering Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending ML Team Review
**Last Updated**: 2025-11-16
**Version**: 1.0
**Priority**: P1 (High Priority for Advanced Threat Detection)
**Authoritative Sources**:
- "Anomaly Detection: A Survey" by Chandola, Banerjee, and Kumar (2009)
- "Machine Learning for Cybersecurity Cookbook" by Emmanuel Tsukerman
- NIST AI Risk Management Framework
- Gartner UEBA Market Guide
- Industry Best Practices for SIEM ML Integration

---

## 1. Executive Summary

### 1.1 Purpose

This document defines comprehensive requirements for Machine Learning (ML) capabilities within the Cerberus SIEM system. ML enables detection of unknown threats, behavioral anomalies, and sophisticated attack patterns that rule-based systems cannot identify.

**Critical Business Drivers**:
- **Zero-Day Threat Detection**: Identify previously unseen attack patterns
- **Insider Threat Detection**: Detect abnormal user behavior deviating from baselines
- **Reduce False Positives**: ML-assisted rule tuning improves detection accuracy
- **Automated Baselining**: Learn normal behavior without manual tuning
- **Advanced Persistent Threats (APTs)**: Detect subtle, long-term attack campaigns

### 1.2 Scope

**In Scope**:
- Anomaly detection models (statistical, isolation forest, autoencoders)
- Baseline learning and behavioral analysis
- Model lifecycle management (training, deployment, monitoring)
- Feature engineering and extraction from security events
- ML-generated alerts with explainability
- Model performance tracking and drift detection
- Integration with rule-based detection (hybrid approach)

**Out of Scope** (Future Enhancements):
- Deep learning models (neural networks, LSTMs) - Phase 2
- Federated learning across multiple Cerberus instances - Phase 3
- Automated threat hunting with reinforcement learning - Phase 3
- Real-time model serving at >100K EPS - Phase 2

### 1.3 Current Implementation Analysis

**Existing ML Components** (as of 2025-11-16):

| Component | File | Status | Coverage |
|-----------|------|--------|----------|
| Anomaly Detection System | `ml/system.go` | ✅ Implemented | Core ML orchestration, dual-mode (simple/continuous) |
| Z-Score Detector | `ml/zscore_detector.go` | ✅ Implemented | Statistical anomaly detection |
| IQR Detector | `ml/iqr_detector.go` | ✅ Implemented | Interquartile range outlier detection |
| Isolation Forest | `ml/isolation_forest.go` | ✅ Implemented | Tree-based anomaly detection |
| Feature Extraction | `ml/feature_extractor.go` | ✅ Implemented | Automatic feature extraction from events |
| Feature Normalization | `ml/feature_normalizer.go` | ✅ Implemented | Z-score, min-max normalization |
| Training Pipeline | `ml/training_pipeline.go` | ✅ Implemented | Batch and continuous learning |
| Ensemble Engine | `ml/ensemble_engine.go` | ✅ Implemented | Multi-model voting and consensus |
| Feature Caching | `ml/feature_cache.go` | ✅ Implemented | Redis and in-memory caching |
| ML API | `api/ml_*.go` | ✅ Implemented | REST API for ML management |
| ML Frontend | `frontend/src/pages/ML/` | ✅ Implemented | Dashboard and controls |

**Implementation Gaps Identified**:
1. ❌ Model persistence across restarts (models retrained on every restart)
2. ❌ Supervised learning capabilities (all models unsupervised)
3. ⚠️ Limited explainability (no SHAP/LIME integration)
4. ⚠️ No A/B testing framework for model comparison
5. ❌ Missing GPU acceleration support
6. ⚠️ No adversarial robustness testing
7. ❌ AutoML capabilities for hyperparameter tuning

**Configuration** (from `config.yaml`):
```yaml
ml:
  enabled: true
  mode: "simple" # or "continuous"
  model_path: "./data/ml_models"
  training_data_dir: "./data/ml_training"
  batch_size: 100
  threshold: 0.7
  update_interval: 60
  feature_cache_size: 10000
  algorithms:
    - "zscore"
    - "iqr"
    - "isolation_forest"
  training_interval: 24
  retrain_threshold: 1000
  enable_drift_detection: true
  anomaly_threshold: 0.7
  min_training_samples: 100
```

---

## 2. Functional Requirements

### 2.1 Anomaly Detection Models

#### FR-ML-001: Statistical Anomaly Detection (Z-Score)

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED
**Owner**: ML Team

**Requirement Statement**:
System MUST support statistical anomaly detection using Z-score analysis to identify events with metric values exceeding N standard deviations from the mean.

**Rationale**:
- Z-score is computationally efficient (O(1) per detection)
- Well-understood statistical method with predictable behavior
- Effective for detecting outliers in normally distributed metrics
- No training data required (online algorithm)

**Use Cases**:
1. **Network Traffic Anomalies**: Detect bytes sent/received exceeding 3σ from baseline
2. **Failed Login Spikes**: Identify authentication attempts >2σ above normal
3. **Process CPU Usage**: Flag processes consuming >3σ CPU
4. **API Request Rates**: Detect API abuse (requests >4σ from mean)

**Specification**:

**Algorithm**:
```
Given: Metric value x, running mean μ, running standard deviation σ
Z-score = (x - μ) / σ

IF |Z-score| > threshold THEN anomaly detected
```

**Configuration Parameters**:
- `threshold`: Number of standard deviations (default: 3.0, configurable 1.0-5.0)
- `window_size`: Number of samples for running statistics (default: 1000)
- `min_samples`: Minimum samples before detection starts (default: 30)

**Current Implementation**: `ml/zscore_detector.go:25-87`
```go
type ZScoreConfig struct {
    Threshold float64 // Z-score threshold (default: 3.0)
}

type ZScoreDetector struct {
    config  *ZScoreConfig
    stats   map[string]*RunningStats
    mu      sync.RWMutex
}

// Detect calculates Z-score and flags anomalies
func (z *ZScoreDetector) Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error)
```

**Acceptance Criteria**:
- [x] Z-score calculated correctly for numeric features
- [x] Running mean and stddev updated incrementally
- [x] Anomaly flagged when |z-score| > threshold
- [x] Separate statistics maintained per feature
- [x] Thread-safe concurrent access
- [ ] Configurable window size for rolling statistics
- [ ] Warm-up period enforcement (min_samples)
- [ ] Statistics persistence across restarts

**Test Requirements**:
```go
// TEST-ML-001: Z-score anomaly detection
func TestZScoreDetector_AnomalyDetection(t *testing.T) {
    detector := NewZScoreDetector(&ZScoreConfig{Threshold: 3.0})

    // Train with normal data (mean=100, stddev=10)
    for i := 0; i < 100; i++ {
        features := &FeatureVector{
            Features: map[string]float64{"bytes_sent": 100 + rand.NormFloat64()*10},
        }
        detector.Train(ctx, features)
    }

    // Test normal value (within 3σ)
    normal := &FeatureVector{Features: map[string]float64{"bytes_sent": 120}}
    result, _ := detector.Detect(ctx, normal)
    assert.False(t, result.IsAnomaly, "Normal value incorrectly flagged")

    // Test anomaly (>3σ from mean)
    anomaly := &FeatureVector{Features: map[string]float64{"bytes_sent": 150}}
    result, _ = detector.Detect(ctx, anomaly)
    assert.True(t, result.IsAnomaly, "Anomaly not detected")
    assert.Greater(t, result.Score, 0.8, "Anomaly score too low")
}

// TEST-ML-002: Z-score warm-up period
func TestZScoreDetector_WarmUpPeriod(t *testing.T) {
    detector := NewZScoreDetector(&ZScoreConfig{
        Threshold: 3.0,
        MinSamples: 30,
    })

    // With <30 samples, should not flag anomalies
    for i := 0; i < 20; i++ {
        features := &FeatureVector{Features: map[string]float64{"metric": float64(i)}}
        detector.Train(ctx, features)
    }

    extreme := &FeatureVector{Features: map[string]float64{"metric": 1000}}
    result, _ := detector.Detect(ctx, extreme)
    assert.False(t, result.IsAnomaly, "Anomaly detected during warm-up period")
}
```

**TBDs**:
- [ ] **TBD-ML-001**: Optimal window size for different metric types (Owner: ML Team, Deadline: Week 3)
- [ ] **TBD-ML-002**: Handling seasonal patterns (daily/weekly cycles) (Owner: ML Team, Deadline: Week 4)

---

#### FR-ML-002: IQR (Interquartile Range) Outlier Detection

**Priority**: P1 (High)
**Status**: ✅ IMPLEMENTED
**Owner**: ML Team

**Requirement Statement**:
System MUST support IQR-based outlier detection to identify events falling outside Q1 - 1.5×IQR or Q3 + 1.5×IQR bounds.

**Rationale**:
- IQR is robust to extreme outliers (not affected by outliers like mean/stddev)
- Works well for skewed distributions (where Z-score fails)
- Standard statistical method (widely accepted)
- Tukey's method for outlier detection (1977)

**Use Cases**:
1. **File Size Anomalies**: Detect unusually large file transfers (right-skewed distribution)
2. **Login Duration**: Identify sessions with abnormal duration (skewed data)
3. **Process Memory**: Detect memory leaks (non-normal distribution)

**Specification**:

**Algorithm**:
```
Given: Sorted metric values
Q1 = 25th percentile
Q3 = 75th percentile
IQR = Q3 - Q1

Lower bound = Q1 - (multiplier × IQR)
Upper bound = Q3 + (multiplier × IQR)

IF value < lower_bound OR value > upper_bound THEN outlier detected
```

**Configuration Parameters**:
- `multiplier`: IQR multiplier (default: 1.5, configurable 1.0-3.0)
  - 1.5 = mild outliers (Tukey standard)
  - 3.0 = extreme outliers

**Current Implementation**: `ml/iqr_detector.go:18-90`
```go
type IQRConfig struct {
    Multiplier float64 // IQR multiplier (default: 1.5)
}

type IQRDetector struct {
    config *IQRConfig
    data   map[string][]float64 // Historical data for percentile calculation
    mu     sync.RWMutex
}

// Detect calculates quartiles and detects outliers
func (iqr *IQRDetector) Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error)
```

**Acceptance Criteria**:
- [x] Quartiles (Q1, Q3) calculated correctly
- [x] IQR bounds computed accurately
- [x] Outliers detected beyond bounds
- [x] Separate bounds per feature
- [x] Thread-safe data access
- [ ] Sliding window for historical data (prevent unbounded growth)
- [ ] Percentile calculation optimization (use approximate algorithms for large datasets)

**Test Requirements**:
```go
// TEST-ML-003: IQR outlier detection
func TestIQRDetector_OutlierDetection(t *testing.T) {
    detector := NewIQRDetector(&IQRConfig{Multiplier: 1.5})

    // Train with skewed data
    data := []float64{1, 2, 2, 3, 3, 3, 4, 4, 5, 100} // 100 is outlier
    for _, val := range data {
        features := &FeatureVector{Features: map[string]float64{"response_time": val}}
        detector.Train(ctx, features)
    }

    // Test normal value (within IQR bounds)
    normal := &FeatureVector{Features: map[string]float64{"response_time": 3}}
    result, _ := detector.Detect(ctx, normal)
    assert.False(t, result.IsAnomaly)

    // Test outlier
    outlier := &FeatureVector{Features: map[string]float64{"response_time": 50}}
    result, _ = detector.Detect(ctx, outlier)
    assert.True(t, result.IsAnomaly)
}
```

---

#### FR-ML-003: Isolation Forest Anomaly Detection

**Priority**: P1 (High)
**Status**: ✅ IMPLEMENTED
**Owner**: ML Team

**Requirement Statement**:
System MUST support Isolation Forest algorithm for detecting anomalies in high-dimensional feature spaces using random tree partitioning.

**Rationale**:
- Effective for multi-dimensional anomalies (multiple features combined)
- Scalable to large datasets (O(n log n) training, O(log n) detection)
- No assumptions about data distribution
- Industry standard (Liu, Ting, Zhou 2008 - widely cited)

**Use Cases**:
1. **User Behavior Profiling**: Combined features (login time, location, device, actions)
2. **Multi-Metric Anomalies**: Simultaneous spikes in CPU + network + disk
3. **Complex Attack Patterns**: Correlation of process, network, and file activity

**Specification**:

**Algorithm**:
```
Training:
1. Build N random isolation trees
2. Each tree: Recursively partition data by random feature + threshold
3. Store tree structure for detection

Detection:
1. Compute average path length across all trees
2. Shorter path = easier to isolate = anomaly
3. Anomaly score = 2^(-E[path_length] / c(n))
   where c(n) = average path length of unsuccessful search
```

**Configuration Parameters**:
- `num_trees`: Number of isolation trees (default: 100, range: 50-500)
- `subsample_size`: Samples per tree (default: 256, range: 100-1000)
- `contamination`: Expected anomaly ratio (default: 0.1 = 10%)
- `max_tree_depth`: Maximum tree depth (default: auto, range: 5-20)

**Current Implementation**: `ml/isolation_forest.go:23-246`
```go
type IsolationForestConfig struct {
    NumTrees      int     // Number of isolation trees (default: 100)
    SubsampleSize int     // Subsample size per tree (default: 256)
    Contamination float64 // Expected anomaly ratio (default: 0.1)
    Logger        *zap.SugaredLogger
}

type IsolationForest struct {
    config     *IsolationForestConfig
    trees      []*IsolationTree
    isTrained  bool
    threshold  float64 // Computed from contamination
    mu         sync.RWMutex
}

// Detect calculates anomaly score from average path length
func (iforest *IsolationForest) Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error)
```

**Acceptance Criteria**:
- [x] Isolation trees built from training data
- [x] Random feature/threshold selection
- [x] Path length calculation for new samples
- [x] Anomaly score normalization (0-1 range)
- [x] Threshold computed from contamination parameter
- [x] Thread-safe tree access
- [ ] Model serialization (save/load trained forest)
- [ ] Incremental tree updates (online learning)
- [ ] Feature importance calculation

**Test Requirements**:
```go
// TEST-ML-004: Isolation Forest training and detection
func TestIsolationForest_AnomalyDetection(t *testing.T) {
    config := &IsolationForestConfig{
        NumTrees:      10,
        SubsampleSize: 50,
        Contamination: 0.1,
    }
    iforest := NewIsolationForest(config)

    // Train with normal multi-dimensional data
    for i := 0; i < 100; i++ {
        features := &FeatureVector{
            Features: map[string]float64{
                "cpu":     50 + rand.NormFloat64()*5,
                "memory":  1000 + rand.NormFloat64()*100,
                "network": 100 + rand.NormFloat64()*10,
            },
        }
        iforest.Train(ctx, features)
    }

    // Test normal sample
    normal := &FeatureVector{
        Features: map[string]float64{"cpu": 52, "memory": 1050, "network": 105},
    }
    result, _ := iforest.Detect(ctx, normal)
    assert.False(t, result.IsAnomaly)
    assert.Less(t, result.Score, 0.6)

    // Test multi-dimensional anomaly
    anomaly := &FeatureVector{
        Features: map[string]float64{"cpu": 100, "memory": 5000, "network": 1000},
    }
    result, _ = iforest.Detect(ctx, anomaly)
    assert.True(t, result.IsAnomaly)
    assert.Greater(t, result.Score, 0.7)
}

// TEST-ML-005: Isolation Forest contamination threshold
func TestIsolationForest_ContaminationThreshold(t *testing.T) {
    config := &IsolationForestConfig{
        NumTrees:      10,
        SubsampleSize: 50,
        Contamination: 0.05, // Expect 5% anomalies
    }
    iforest := NewIsolationForest(config)

    // Train with 95% normal + 5% anomalies
    normalCount := 95
    anomalyCount := 5

    for i := 0; i < normalCount; i++ {
        normal := &FeatureVector{Features: map[string]float64{"metric": rand.NormFloat64()*10}}
        iforest.Train(ctx, normal)
    }

    for i := 0; i < anomalyCount; i++ {
        anomaly := &FeatureVector{Features: map[string]float64{"metric": 100 + rand.Float64()*50}}
        iforest.Train(ctx, anomaly)
    }

    // Verify threshold captures approximately contamination rate
    // (Statistical test - may have variance)
    detectedAnomalies := 0
    testSamples := 100
    for i := 0; i < testSamples; i++ {
        var features *FeatureVector
        if i < 95 {
            features = &FeatureVector{Features: map[string]float64{"metric": rand.NormFloat64()*10}}
        } else {
            features = &FeatureVector{Features: map[string]float64{"metric": 100 + rand.Float64()*50}}
        }
        result, _ := iforest.Detect(ctx, features)
        if result.IsAnomaly {
            detectedAnomalies++
        }
    }

    // Allow 50% margin of error (contamination-based threshold is approximate)
    expectedAnomalies := 5
    assert.InDelta(t, expectedAnomalies, detectedAnomalies, float64(expectedAnomalies)*0.5)
}
```

**TBDs**:
- [ ] **TBD-ML-003**: Optimal tree count vs. accuracy trade-off (Owner: ML Team, Deadline: Week 3)
- [ ] **TBD-ML-004**: Feature importance calculation method (Owner: ML Team, Deadline: Week 4)

---

### 2.2 Model Management

#### FR-ML-004: Model Lifecycle Management

**Priority**: P0 (Critical)
**Status**: ⚠️ PARTIAL (No persistence, basic training implemented)
**Owner**: ML Team

**Requirement Statement**:
System MUST manage the complete lifecycle of ML models including creation, training, deployment, versioning, monitoring, and retirement.

**Rationale**:
- Production ML systems require versioned, auditable models
- Model rollback capability for regression scenarios
- A/B testing requires multiple concurrent model versions
- Compliance and explainability require model provenance tracking

**Model Lifecycle States**:
```
CREATED → TRAINING → VALIDATING → DEPLOYED → MONITORING → DEPRECATED → RETIRED
                ↓          ↓           ↓
              FAILED    FAILED    ROLLBACK → DEPLOYED (previous version)
```

**Specification**:

**Model Metadata Schema**:
```json
{
  "model_id": "zscore-network-v1",
  "algorithm": "zscore",
  "version": "1.0.0",
  "created_at": "2025-01-16T12:00:00Z",
  "trained_at": "2025-01-16T14:00:00Z",
  "deployed_at": "2025-01-16T15:00:00Z",
  "status": "deployed",
  "training_config": {
    "threshold": 3.0,
    "min_samples": 100,
    "training_samples": 50000
  },
  "performance_metrics": {
    "precision": 0.85,
    "recall": 0.78,
    "f1_score": 0.81,
    "false_positive_rate": 0.02
  },
  "feature_list": ["bytes_sent", "bytes_received", "duration"],
  "training_duration_sec": 120,
  "deployment_count": 1,
  "last_prediction_at": "2025-01-16T18:30:00Z"
}
```

**Lifecycle Operations**:

1. **Create Model**:
   - API: `POST /api/v1/ml/models`
   - Input: Algorithm, configuration, feature list
   - Output: Model ID, initial status (CREATED)
   - Validation: Algorithm supported, config valid, features exist

2. **Train Model**:
   - API: `POST /api/v1/ml/models/{id}/train`
   - Input: Training dataset reference or fetch from event storage
   - Output: Training metrics, status (TRAINING → VALIDATING → DEPLOYED)
   - Validation: Sufficient training samples, valid feature data
   - **Gap**: Currently no API endpoint, training automatic

3. **Deploy Model**:
   - API: `POST /api/v1/ml/models/{id}/deploy`
   - Input: Deployment strategy (replace/canary/blue-green)
   - Output: Deployment status
   - Validation: Model trained, validation passed
   - **Gap**: Not implemented - models auto-deployed

4. **Undeploy/Retire Model**:
   - API: `DELETE /api/v1/ml/models/{id}`
   - Input: Model ID, optional replacement model ID
   - Output: Retirement status
   - Validation: No active traffic to model
   - **Gap**: Not implemented

5. **Rollback Model**:
   - API: `POST /api/v1/ml/models/{id}/rollback`
   - Input: Target version
   - Output: Rollback status
   - Validation: Target version exists and deployable
   - **Gap**: No versioning implemented

**Current Implementation Gaps**:
```go
// NEEDED: Model persistence layer
type ModelStorage interface {
    SaveModel(model *Model) error
    LoadModel(modelID string) (*Model, error)
    ListModels(filter ModelFilter) ([]*Model, error)
    UpdateModelStatus(modelID string, status ModelStatus) error
    DeleteModel(modelID string) error
}

// NEEDED: Model versioning
type ModelVersion struct {
    ModelID       string
    Version       string
    CreatedAt     time.Time
    TrainedAt     time.Time
    DeployedAt    *time.Time
    RetiredAt     *time.Time
    Config        map[string]interface{}
    Metrics       *ModelMetrics
    ArtifactPath  string // Path to serialized model
}
```

**Acceptance Criteria**:
- [ ] Models survive system restarts (persisted to disk/database)
- [ ] Multiple model versions maintained (at least 3 historical versions)
- [ ] Deployment strategies supported (replace, canary, blue-green)
- [ ] Rollback to previous version within 60 seconds
- [ ] Model metadata queryable via API
- [ ] Model status transitions audited (logged)
- [ ] Model artifacts stored in versioned storage

**Test Requirements**:
```go
// TEST-ML-006: Model persistence across restarts
func TestModelLifecycle_Persistence(t *testing.T) {
    // Create and train model
    model := createAndTrainModel(t, "zscore", &ZScoreConfig{Threshold: 3.0})
    modelID := model.ID

    // Persist model
    storage := NewModelStorage(dbConn)
    err := storage.SaveModel(model)
    require.NoError(t, err)

    // Simulate restart (create new storage instance)
    newStorage := NewModelStorage(dbConn)

    // Load model
    loadedModel, err := newStorage.LoadModel(modelID)
    require.NoError(t, err)
    assert.Equal(t, model.Config, loadedModel.Config)
    assert.Equal(t, model.Version, loadedModel.Version)

    // Verify model still detects anomalies correctly
    anomaly := &FeatureVector{Features: map[string]float64{"metric": 1000}}
    result, _ := loadedModel.Detector.Detect(ctx, anomaly)
    assert.True(t, result.IsAnomaly)
}

// TEST-ML-007: Model versioning and rollback
func TestModelLifecycle_Versioning(t *testing.T) {
    storage := NewModelStorage(dbConn)

    // Deploy v1.0.0
    v1 := createAndTrainModel(t, "zscore", &ZScoreConfig{Threshold: 3.0})
    v1.Version = "1.0.0"
    storage.SaveModel(v1)
    storage.Deploy(v1.ID)

    // Deploy v2.0.0 with different config
    v2 := createAndTrainModel(t, "zscore", &ZScoreConfig{Threshold: 2.5})
    v2.Version = "2.0.0"
    storage.SaveModel(v2)
    storage.Deploy(v2.ID)

    // Verify v2 is active
    active, _ := storage.GetActiveModel("zscore")
    assert.Equal(t, "2.0.0", active.Version)

    // Rollback to v1
    err := storage.Rollback(v2.ID, v1.ID)
    require.NoError(t, err)

    // Verify v1 is active again
    active, _ = storage.GetActiveModel("zscore")
    assert.Equal(t, "1.0.0", active.Version)

    // Verify v2 status updated to DEPRECATED
    v2Status, _ := storage.GetModelStatus(v2.ID)
    assert.Equal(t, ModelStatusDeprecated, v2Status)
}
```

**TBDs**:
- [ ] **TBD-ML-005**: Model storage backend (SQLite, ClickHouse, or dedicated model DB?) (Owner: Architecture Team, Deadline: Week 2)
- [ ] **TBD-ML-006**: Model serialization format (pickle, ONNX, custom binary?) (Owner: ML Team, Deadline: Week 2)
- [ ] **TBD-ML-007**: Maximum model versions retained (default: 5?) (Owner: ML Team, Deadline: Week 3)

---

#### FR-ML-005: Model Performance Tracking

**Priority**: P0 (Critical)
**Status**: ⚠️ PARTIAL (Ensemble tracks basic metrics, no comprehensive tracking)
**Owner**: ML Team + Operations Team

**Requirement Statement**:
System MUST track comprehensive performance metrics for ML models including precision, recall, F1-score, false positive/negative rates, ROC curves, and model drift indicators.

**Rationale**:
- Model performance degrades over time (concept drift)
- False positive rate directly impacts analyst workload
- Compliance requires demonstrable model accuracy
- Continuous monitoring enables proactive retraining

**Performance Metrics**:

| Metric | Formula | Target | Criticality |
|--------|---------|--------|-------------|
| **Precision** | TP / (TP + FP) | ≥0.80 | High (FP impact) |
| **Recall** | TP / (TP + FN) | ≥0.75 | High (missed threats) |
| **F1-Score** | 2 × (P × R) / (P + R) | ≥0.77 | High (balanced) |
| **False Positive Rate** | FP / (FP + TN) | ≤0.05 | Critical |
| **False Negative Rate** | FN / (FN + TP) | ≤0.10 | Critical |
| **AUC-ROC** | Area under ROC curve | ≥0.85 | Medium |
| **Drift Score** | KL divergence | <0.1 | High |

**Confusion Matrix Tracking**:
```
                Predicted Positive  Predicted Negative
Actual Positive       TP                    FN
Actual Negative       FP                    TN
```

**Specification**:

**Metric Collection**:
```go
type ModelMetrics struct {
    ModelID           string
    Timestamp         time.Time
    WindowDuration    time.Duration // Metrics calculated over this window

    // Classification Metrics
    TruePositives     int64
    TrueNegatives     int64
    FalsePositives    int64
    FalseNegatives    int64

    // Derived Metrics
    Precision         float64
    Recall            float64
    F1Score           float64
    FalsePositiveRate float64
    FalseNegativeRate float64
    Accuracy          float64

    // ROC/AUC
    AUCROC            float64
    ROCCurve          []ROCPoint // For plotting

    // Drift Detection
    DriftScore        float64
    DriftDetected     bool
    FeatureDrift      map[string]float64 // Per-feature drift scores

    // Performance
    AvgPredictionTime time.Duration
    TotalPredictions  int64
}

type ROCPoint struct {
    Threshold         float64
    TruePositiveRate  float64
    FalsePositiveRate float64
}
```

**Metric Calculation Workflow**:
```
1. Event processed → ML prediction (anomaly score)
2. Store prediction in "pending validation" queue
3. Analyst reviews alert → provides feedback (TP/FP)
4. Feedback updates confusion matrix
5. Metrics recalculated every 1 hour (rolling window)
6. Metrics stored in time-series database
7. Drift detection triggered if metrics degrade >10%
```

**Current Implementation**:
```go
// ml/training_pipeline.go:48-55
type TrainingPerformance struct {
    Timestamp        time.Time
    TrainingDuration time.Duration
    SampleCount      int64
    ValidationScore  float64
    DriftDetected    bool
    AlgorithmMetrics map[string]float64
}
```

**Gaps**:
- ❌ No confusion matrix tracking
- ❌ No analyst feedback loop
- ❌ No ROC curve calculation
- ❌ No per-feature drift tracking
- ⚠️ Basic drift detection (boolean flag only)

**Acceptance Criteria**:
- [ ] Confusion matrix updated with analyst feedback
- [ ] Precision/Recall/F1 calculated every 1 hour
- [ ] False positive rate tracked and alerted if >5%
- [ ] ROC curve generated for visualization
- [ ] AUC-ROC calculated and tracked over time
- [ ] Model drift detected using KL divergence or PSI
- [ ] Metrics persisted in time-series storage (ClickHouse)
- [ ] Metrics API endpoint returns 30-day history
- [ ] Dashboard displays real-time model performance

**Test Requirements**:
```go
// TEST-ML-008: Model performance metrics calculation
func TestModelMetrics_ConfusionMatrix(t *testing.T) {
    metrics := NewModelMetrics("zscore-network-v1")

    // Simulate predictions and analyst feedback
    // TP: Model predicted anomaly (score 0.9), analyst confirmed
    metrics.RecordPrediction(0.9, true, true)

    // TN: Model predicted normal (score 0.2), analyst confirmed
    metrics.RecordPrediction(0.2, false, true)

    // FP: Model predicted anomaly (score 0.8), analyst rejected
    metrics.RecordPrediction(0.8, true, false)

    // FN: Model predicted normal (score 0.4), but was actual anomaly
    metrics.RecordPrediction(0.4, false, true)

    // Calculate metrics
    computed := metrics.Calculate()

    assert.Equal(t, int64(1), computed.TruePositives)
    assert.Equal(t, int64(1), computed.TrueNegatives)
    assert.Equal(t, int64(1), computed.FalsePositives)
    assert.Equal(t, int64(1), computed.FalseNegatives)

    // Precision = TP / (TP + FP) = 1 / (1 + 1) = 0.5
    assert.InDelta(t, 0.5, computed.Precision, 0.01)

    // Recall = TP / (TP + FN) = 1 / (1 + 1) = 0.5
    assert.InDelta(t, 0.5, computed.Recall, 0.01)

    // F1 = 2 * (P * R) / (P + R) = 2 * (0.5 * 0.5) / (0.5 + 0.5) = 0.5
    assert.InDelta(t, 0.5, computed.F1Score, 0.01)
}

// TEST-ML-009: Model drift detection
func TestModelMetrics_DriftDetection(t *testing.T) {
    metrics := NewModelMetrics("zscore-network-v1")

    // Baseline: 80% precision for 7 days
    for i := 0; i < 700; i++ {
        if i%10 < 8 { // 80% TP
            metrics.RecordPrediction(0.9, true, true)
        } else { // 20% FP
            metrics.RecordPrediction(0.9, true, false)
        }
    }
    baseline := metrics.Calculate()
    assert.InDelta(t, 0.8, baseline.Precision, 0.05)

    // Drift: Precision drops to 60% over next day
    for i := 0; i < 100; i++ {
        if i%10 < 6 { // 60% TP
            metrics.RecordPrediction(0.9, true, true)
        } else { // 40% FP
            metrics.RecordPrediction(0.9, true, false)
        }
    }
    drifted := metrics.Calculate()

    // Verify drift detected (>10% degradation)
    assert.True(t, drifted.DriftDetected)
    assert.Greater(t, drifted.DriftScore, 0.1)
    assert.InDelta(t, 0.6, drifted.Precision, 0.05)
}
```

**TBDs**:
- [ ] **TBD-ML-008**: Analyst feedback mechanism (API, UI workflow) (Owner: UX Team, Deadline: Week 3)
- [ ] **TBD-ML-009**: Drift detection threshold (10% degradation?) (Owner: ML Team, Deadline: Week 3)
- [ ] **TBD-ML-010**: Metric aggregation window (1 hour, 24 hours, 7 days?) (Owner: ML Team, Deadline: Week 3)

---

### 2.3 Training Data Management

#### FR-ML-006: Training Dataset Creation and Validation

**Priority**: P1 (High)
**Status**: ✅ IMPLEMENTED (Basic fetching), ⚠️ GAPS (No validation, labeling)
**Owner**: ML Team

**Requirement Statement**:
System MUST support creation, validation, versioning, and quality assurance of training datasets including data sampling, labeling, and feature engineering pipelines.

**Rationale**:
- Quality of training data directly determines model accuracy
- Biased/poor training data leads to biased models
- Versioned datasets enable reproducible training
- Labeled data required for supervised learning (future)

**Training Dataset Requirements**:

| Requirement | Specification | Status |
|-------------|---------------|--------|
| **Size** | Minimum 1,000 samples per algorithm | ✅ Configurable |
| **Recency** | Last 30 days of events (default) | ⚠️ Not enforced |
| **Diversity** | Multiple event types, sources | ❌ Not validated |
| **Balance** | 90% normal, 10% anomalies (for supervised) | ❌ Not applicable (unsupervised only) |
| **Quality** | No missing features, no duplicates | ❌ Not validated |
| **Versioning** | Dataset ID + timestamp | ❌ Not implemented |

**Specification**:

**Dataset Creation Workflow**:
```
1. Define selection criteria:
   - Time range (e.g., last 30 days)
   - Event types (e.g., authentication, network)
   - Sampling strategy (random, stratified, time-based)

2. Fetch events from ClickHouse
   - Query: SELECT * FROM events WHERE timestamp >= now() - INTERVAL 30 DAY
   - Apply sampling (e.g., 10% random sample)

3. Validate dataset:
   - Check minimum sample count
   - Check feature coverage (all required features present)
   - Check for duplicates
   - Check for class imbalance (if supervised)

4. Store dataset metadata:
   - Dataset ID
   - Creation timestamp
   - Selection criteria
   - Sample count
   - Feature list
   - Quality metrics

5. Return dataset reference for training
```

**Current Implementation**: `ml/system.go:434-494`
```go
func (stp *SimpleTrainingPipeline) fetchTrainingData(ctx context.Context) ([]*core.Event, error) {
    // Get total event count
    totalCount, err := stp.eventStorage.GetEventCount()
    if err != nil {
        return nil, fmt.Errorf("failed to get event count: %w", err)
    }

    // Fetch up to 10k events for training
    maxEventsToFetch := 10000
    if totalCount < int64(maxEventsToFetch) {
        maxEventsToFetch = int(totalCount)
    }

    // Fetch events in batches
    const batchSize = 1000
    var allEvents []*core.Event
    for offset := 0; offset < maxEventsToFetch; offset += batchSize {
        events, err := stp.eventStorage.GetEvents(limit, offset)
        // ... batch fetching logic
    }

    return allEvents, nil
}
```

**Gaps Identified**:
1. ❌ No time range filtering (fetches all events, not recent)
2. ❌ No event type filtering
3. ❌ No sampling strategy (always fetches first N events)
4. ❌ No quality validation
5. ❌ No dataset versioning
6. ❌ No label support (for future supervised learning)

**Enhanced Dataset Schema** (Needed):
```go
type TrainingDataset struct {
    DatasetID      string
    Version        string
    CreatedAt      time.Time
    CreatedBy      string

    // Selection Criteria
    TimeRangeStart time.Time
    TimeRangeEnd   time.Time
    EventTypes     []string
    SourceFilters  map[string]string
    SamplingRate   float64 // 0.1 = 10% sample

    // Dataset Statistics
    TotalSamples   int64
    FeatureList    []string
    LabeledSamples int64 // For supervised learning

    // Quality Metrics
    MissingFeatureRate float64 // % of samples with missing features
    DuplicateRate      float64 // % of duplicate samples
    ClassDistribution  map[string]int64 // Label distribution

    // Storage
    StoragePath    string // Path to dataset file (Parquet, CSV)
}

type DatasetValidator interface {
    ValidateSize(dataset *TrainingDataset, minSamples int) error
    ValidateFeatures(dataset *TrainingDataset, requiredFeatures []string) error
    ValidateQuality(dataset *TrainingDataset) (*QualityReport, error)
    ValidateBalance(dataset *TrainingDataset, maxImbalance float64) error
}
```

**Acceptance Criteria**:
- [ ] Datasets versioned with unique ID + timestamp
- [ ] Time range filtering applied (last N days configurable)
- [ ] Event type filtering supported
- [ ] Sampling strategies: random, stratified, time-weighted
- [ ] Minimum sample count enforced (default: 1,000)
- [ ] Feature coverage validated (no missing required features)
- [ ] Duplicate detection and removal
- [ ] Dataset metadata stored and queryable
- [ ] Dataset quality report generated
- [ ] Labeled data support for supervised learning (Phase 2)

**Test Requirements**:
```go
// TEST-ML-010: Training dataset creation and validation
func TestTrainingDataset_Creation(t *testing.T) {
    creator := NewDatasetCreator(eventStorage)

    criteria := &DatasetCriteria{
        TimeRangeStart: time.Now().AddDate(0, 0, -30), // Last 30 days
        TimeRangeEnd:   time.Now(),
        EventTypes:     []string{"authentication", "network"},
        SamplingRate:   0.1, // 10% sample
        MinSamples:     1000,
    }

    dataset, err := creator.CreateDataset(ctx, criteria)
    require.NoError(t, err)

    // Verify dataset meets criteria
    assert.GreaterOrEqual(t, dataset.TotalSamples, int64(1000))
    assert.NotEmpty(t, dataset.DatasetID)
    assert.NotEmpty(t, dataset.FeatureList)

    // Verify time range
    for _, event := range dataset.Events {
        assert.True(t, event.Timestamp.After(criteria.TimeRangeStart))
        assert.True(t, event.Timestamp.Before(criteria.TimeRangeEnd))
    }
}

// TEST-ML-011: Dataset quality validation
func TestTrainingDataset_QualityValidation(t *testing.T) {
    validator := NewDatasetValidator()

    // Create dataset with quality issues
    dataset := &TrainingDataset{
        Events: []*Event{
            {Fields: map[string]interface{}{"cpu": 50}}, // Missing "memory" feature
            {Fields: map[string]interface{}{"cpu": 50, "memory": 1000}},
            {Fields: map[string]interface{}{"cpu": 50, "memory": 1000}}, // Duplicate
        },
    }

    report, err := validator.ValidateQuality(dataset)
    require.NoError(t, err)

    // Verify quality issues detected
    assert.Greater(t, report.MissingFeatureRate, 0.0)
    assert.Greater(t, report.DuplicateRate, 0.0)
    assert.Contains(t, report.Issues, "Missing features in 33% of samples")
    assert.Contains(t, report.Issues, "Duplicates detected: 33%")
}
```

**TBDs**:
- [ ] **TBD-ML-011**: Default time range for training data (30 days? 90 days?) (Owner: ML Team, Deadline: Week 2)
- [ ] **TBD-ML-012**: Maximum dataset size (memory constraints) (Owner: ML Team, Deadline: Week 2)
- [ ] **TBD-ML-013**: Dataset storage format (Parquet, CSV, binary?) (Owner: ML Team, Deadline: Week 3)

---

### 2.4 Feature Engineering

#### FR-ML-007: Automatic Feature Extraction

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED (Comprehensive)
**Owner**: ML Team

**Requirement Statement**:
System MUST automatically extract numeric features from raw security events including statistical, temporal, network, and behavioral features suitable for ML algorithms.

**Rationale**:
- Manual feature engineering is time-consuming and error-prone
- Automatic extraction enables rapid deployment of ML models
- Standardized features ensure consistency across models
- Feature reuse improves efficiency

**Feature Categories**:

| Category | Examples | Current Status |
|----------|----------|----------------|
| **Statistical** | Event frequency, unique counts | ✅ Implemented |
| **Temporal** | Hour of day, day of week, time since last event | ✅ Implemented |
| **Network** | Bytes sent/received, packet count, port number | ✅ Implemented |
| **String** | Field length, entropy, character distribution | ✅ Implemented |
| **Behavioral** | Deviation from baseline, velocity, burst rate | ⚠️ Partial |

**Current Implementation**: `ml/feature_extractor.go`, `ml/extractors.go`, `ml/network_extractor.go`, `ml/temporal_extractor.go`

**Example Features**:
```go
// From ml/extractors.go
type FeatureVector struct {
    EventID   string
    Timestamp time.Time
    Features  map[string]float64
}

// Extracted features:
features := map[string]float64{
    // Statistical
    "event_frequency": 15.5,
    "unique_users": 5,
    "unique_ips": 12,

    // Temporal
    "hour_of_day": 14,
    "day_of_week": 3, // Wednesday
    "is_weekend": 0,
    "is_business_hours": 1,

    // Network
    "bytes_sent": 1048576,
    "bytes_received": 524288,
    "packet_count": 150,
    "connection_duration_sec": 45.5,

    // String features
    "username_length": 8,
    "username_entropy": 3.2,
    "url_length": 54,

    // Behavioral (future)
    "login_velocity": 5.5, // Logins per hour
    "deviation_from_baseline": 2.3,
}
```

**Feature Extraction Pipeline**:
```go
// ml/feature_extractor.go:42-118
type FeatureExtractorManager struct {
    extractors map[string]FeatureExtractor
    cache      FeatureCache
    logger     *zap.SugaredLogger
}

func (fem *FeatureExtractorManager) ExtractFeatures(ctx context.Context, event *core.Event) (*FeatureVector, error) {
    // Check cache first
    if fem.cache != nil {
        if cached, err := fem.cache.Get(ctx, event.EventID); err == nil && cached != nil {
            return cached, nil
        }
    }

    // Extract features from all registered extractors
    features := make(map[string]float64)
    for name, extractor := range fem.extractors {
        extracted := extractor.Extract(event)
        for k, v := range extracted {
            features[name+"_"+k] = v
        }
    }

    vector := &FeatureVector{
        EventID:   event.EventID,
        Timestamp: event.Timestamp,
        Features:  features,
    }

    // Cache extracted features
    if fem.cache != nil {
        fem.cache.Set(ctx, vector, 1*time.Hour)
    }

    return vector, nil
}
```

**Registered Extractors**:
1. **StatisticalExtractor**: Count, sum, average, min, max
2. **TemporalExtractor**: Time-based features (hour, day, cyclical encoding)
3. **NetworkExtractor**: Network traffic metrics
4. **StringExtractor**: String length, entropy, character distribution
5. **BehavioralExtractor** (future): Baseline deviation, velocity

**Acceptance Criteria**:
- [x] Features extracted from all event types
- [x] Numeric features normalized to float64
- [x] Missing features handled gracefully (default value or skip)
- [x] Feature extraction cached (Redis/memory)
- [x] Extraction errors logged but don't fail entire pipeline
- [x] Custom extractors registerable
- [ ] Feature importance scoring
- [ ] Automatic feature selection (remove low-importance features)

**Test Requirements**:
```go
// TEST-ML-012: Feature extraction from events
func TestFeatureExtractor_ExtractFeatures(t *testing.T) {
    extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{})

    event := &core.Event{
        EventID:   "evt-123",
        Timestamp: time.Date(2025, 1, 16, 14, 30, 0, 0, time.UTC),
        Fields: map[string]interface{}{
            "bytes_sent":     1048576,
            "bytes_received": 524288,
            "username":       "admin",
            "source_ip":      "192.168.1.100",
        },
    }

    features, err := extractor.ExtractFeatures(ctx, event)
    require.NoError(t, err)

    // Verify temporal features
    assert.Equal(t, 14.0, features.Features["temporal_hour_of_day"])
    assert.Equal(t, 4.0, features.Features["temporal_day_of_week"]) // Thursday
    assert.Equal(t, 1.0, features.Features["temporal_is_business_hours"])

    // Verify network features
    assert.Equal(t, 1048576.0, features.Features["network_bytes_sent"])
    assert.Equal(t, 524288.0, features.Features["network_bytes_received"])

    // Verify string features
    assert.Equal(t, 5.0, features.Features["string_username_length"])
    assert.Greater(t, features.Features["string_username_entropy"], 0.0)
}

// TEST-ML-013: Feature extraction caching
func TestFeatureExtractor_Caching(t *testing.T) {
    cache := NewMemoryFeatureCache()
    extractor := NewFeatureExtractorManager(&FeatureExtractorConfig{Cache: cache})

    event := &core.Event{EventID: "evt-123", Fields: map[string]interface{}{"metric": 100}}

    // First extraction
    start := time.Now()
    features1, _ := extractor.ExtractFeatures(ctx, event)
    firstDuration := time.Since(start)

    // Second extraction (should be cached)
    start = time.Now()
    features2, _ := extractor.ExtractFeatures(ctx, event)
    cachedDuration := time.Since(start)

    // Verify cache hit
    assert.Equal(t, features1, features2)
    assert.Less(t, cachedDuration, firstDuration/10, "Cache should be 10x faster")
}
```

---

#### FR-ML-008: Feature Normalization

**Priority**: P1 (High)
**Status**: ✅ IMPLEMENTED
**Owner**: ML Team

**Requirement Statement**:
System MUST normalize extracted features using standard techniques (Z-score, Min-Max, robust scaling) to ensure features are on comparable scales for ML algorithms.

**Rationale**:
- ML algorithms (especially distance-based) are sensitive to feature scales
- Features with large ranges (e.g., bytes: 0-1GB) dominate features with small ranges (e.g., port: 0-65535)
- Normalization improves model convergence and accuracy

**Normalization Methods**:

| Method | Formula | Use Case | Status |
|--------|---------|----------|--------|
| **Z-Score** | (x - μ) / σ | Normally distributed features | ✅ Implemented |
| **Min-Max** | (x - min) / (max - min) | Bounded features (0-1 range) | ✅ Implemented |
| **Robust** | (x - median) / IQR | Features with outliers | ✅ Implemented |
| **Log** | log(x + 1) | Right-skewed distributions | ⚠️ Partial |

**Current Implementation**: `ml/feature_normalizer.go`
```go
type FeatureNormalizerManager struct {
    normalizers map[string]FeatureNormalizer
    stats       map[string]*FeatureStats
    mu          sync.RWMutex
}

func (fnm *FeatureNormalizerManager) NormalizeFeature(method, featureName string, value float64) float64 {
    normalizer := fnm.normalizers[method]
    stats := fnm.stats[featureName]

    return normalizer.Normalize(value, stats)
}
```

**Acceptance Criteria**:
- [x] Z-score normalization implemented
- [x] Min-Max normalization implemented
- [x] Robust normalization implemented
- [x] Feature statistics updated incrementally
- [ ] Per-feature normalization method selection
- [ ] Normalization statistics persisted across restarts

**Test Requirements**:
```go
// TEST-ML-014: Feature normalization
func TestFeatureNormalizer_ZScore(t *testing.T) {
    normalizer := NewFeatureNormalizerManager()

    // Train with data (mean=100, stddev=10)
    for i := 0; i < 100; i++ {
        value := 100 + rand.NormFloat64()*10
        normalizer.UpdateNormalizerStats("metric", value)
    }

    // Normalize value
    normalized := normalizer.NormalizeFeature("zscore", "metric", 120)

    // 120 is 2 stddev above mean → z-score ≈ 2.0
    assert.InDelta(t, 2.0, normalized, 0.5)
}
```

---

### 2.5 Alert Generation from ML

#### FR-ML-009: ML-Generated Alerts with Explainability

**Priority**: P0 (Critical)
**Status**: ⚠️ PARTIAL (Alerts generated, limited explainability)
**Owner**: ML Team + Detection Team

**Requirement Statement**:
System MUST generate security alerts from ML anomaly detections with comprehensive context including anomaly score, contributing features, confidence level, and human-readable explanations.

**Rationale**:
- Analysts need to understand WHY ML flagged an event as anomalous
- Explainability builds trust in ML-generated alerts
- GDPR/CCPA require explainable automated decisions
- Debugging and tuning require visibility into model decisions

**ML Alert Structure**:
```json
{
  "alert_id": "ml-alert-12345",
  "alert_type": "ml_anomaly",
  "timestamp": "2025-01-16T14:30:00Z",
  "severity": "high",

  "event_id": "evt-98765",
  "event_summary": {
    "event_type": "authentication",
    "user": "admin",
    "source_ip": "192.168.1.100",
    "timestamp": "2025-01-16T14:29:58Z"
  },

  "ml_detection": {
    "model_id": "ensemble-behavior-v1",
    "anomaly_score": 0.87,
    "confidence": 0.92,
    "is_anomaly": true,
    "threshold": 0.7,

    "algorithm_results": {
      "zscore": {
        "score": 0.85,
        "decision": "anomaly",
        "contributing_features": ["login_velocity", "bytes_sent"]
      },
      "isolation_forest": {
        "score": 0.90,
        "decision": "anomaly",
        "avg_path_length": 3.2
      },
      "iqr": {
        "score": 0.86,
        "decision": "anomaly",
        "bounds": {"lower": 10, "upper": 200, "value": 450}
      }
    },

    "top_contributing_features": [
      {
        "feature": "login_velocity",
        "value": 15.5,
        "normal_range": [0.5, 3.0],
        "deviation_score": 4.2,
        "explanation": "User logged in 15.5 times per hour, significantly above normal rate of 0.5-3.0 logins/hour"
      },
      {
        "feature": "bytes_sent",
        "value": 10485760,
        "normal_range": [100000, 1000000],
        "deviation_score": 3.8,
        "explanation": "Sent 10MB of data, 10x higher than typical 1MB average"
      }
    ],

    "human_readable_explanation": "This authentication event was flagged as anomalous because the user logged in 15.5 times per hour (normally 0.5-3.0) and sent 10MB of data (normally <1MB). This behavior deviates significantly from the user's historical baseline and may indicate credential compromise or automated activity."
  },

  "recommended_actions": [
    "Review recent activity for user 'admin'",
    "Check if large data transfer was authorized",
    "Investigate source IP 192.168.1.100 for suspicious activity"
  ]
}
```

**Current Implementation Gaps**:
- ✅ Anomaly score calculated
- ✅ Algorithm results from ensemble
- ❌ Top contributing features NOT identified
- ❌ No human-readable explanations
- ❌ No recommended actions
- ❌ No confidence calculation

**Explainability Techniques** (Needed):

1. **Feature Importance (Global)**:
   - Permutation importance: Shuffle feature, measure score drop
   - SHAP values: Shapley Additive Explanations (industry standard)
   - Partial dependence plots

2. **Feature Contribution (Local - per prediction)**:
   - LIME: Local Interpretable Model-agnostic Explanations
   - Feature attribution: Which features pushed score above threshold
   - Counterfactual explanations: "If X were Y, this wouldn't be anomalous"

**Acceptance Criteria**:
- [ ] Anomaly score in range [0, 1] with threshold
- [ ] Confidence score calculated from ensemble agreement
- [ ] Top 5 contributing features identified
- [ ] Feature contributions include normal range and deviation
- [ ] Human-readable explanation generated (template-based)
- [ ] Recommended actions included (rule-based)
- [ ] Alert severity derived from anomaly score
- [ ] Alert includes link to original event
- [ ] Alert metadata stored for feedback loop

**Test Requirements**:
```go
// TEST-ML-015: ML alert generation with explainability
func TestMLAlert_Explainability(t *testing.T) {
    detector := setupEnsembleDetector(t)

    event := &core.Event{
        EventID: "evt-123",
        Fields: map[string]interface{}{
            "login_velocity": 15.5,
            "bytes_sent":     10485760,
            "hour_of_day":    14,
        },
    }

    result, err := detector.Detect(ctx, event)
    require.NoError(t, err)
    assert.True(t, result.IsAnomaly)

    // Generate alert with explainability
    alert := GenerateMLAlert(event, result)

    // Verify anomaly score
    assert.InDelta(t, 0.87, alert.MLDetection.AnomalyScore, 0.1)

    // Verify top contributing features identified
    require.NotEmpty(t, alert.MLDetection.TopContributingFeatures)
    topFeature := alert.MLDetection.TopContributingFeatures[0]
    assert.Equal(t, "login_velocity", topFeature.Feature)
    assert.Equal(t, 15.5, topFeature.Value)
    assert.Greater(t, topFeature.DeviationScore, 3.0)
    assert.NotEmpty(t, topFeature.Explanation)

    // Verify human-readable explanation
    assert.Contains(t, alert.MLDetection.HumanReadableExplanation, "logged in 15.5 times per hour")
    assert.Contains(t, alert.MLDetection.HumanReadableExplanation, "deviates significantly")

    // Verify recommended actions
    assert.NotEmpty(t, alert.RecommendedActions)
    assert.Contains(t, alert.RecommendedActions[0], "Review recent activity")
}
```

**TBDs**:
- [ ] **TBD-ML-014**: Explainability library (SHAP, LIME, custom?) (Owner: ML Team, Deadline: Week 4)
- [ ] **TBD-ML-015**: Explanation template system design (Owner: UX Team, Deadline: Week 4)

---

### 2.6 Integration with Rule-Based Detection

#### FR-ML-010: Hybrid ML-Rule Detection

**Priority**: P1 (High)
**Status**: ⚠️ PARTIAL (Sequential processing, no deep integration)
**Owner**: Detection Team + ML Team

**Requirement Statement**:
System MUST support hybrid detection combining rule-based and ML-based approaches including ML scores as rule conditions, ML-assisted rule tuning, and rule recommendation from ML insights.

**Rationale**:
- Rules excel at known attack patterns (high precision)
- ML excels at unknown/novel patterns (high recall)
- Combining both maximizes detection coverage
- ML can reduce rule false positives

**Hybrid Detection Modes**:

| Mode | Description | Use Case | Priority |
|------|-------------|----------|----------|
| **Sequential** | Rules first, then ML on non-matches | Current implementation | ✅ P0 |
| **Parallel** | Rules and ML run concurrently | High-volume environments | ⚠️ P1 |
| **ML-Assisted Rules** | Rules reference ML scores | Reduce false positives | ❌ P1 |
| **Rule Recommendation** | ML suggests new rules from patterns | Continuous improvement | ❌ P2 |
| **ML-Tuned Thresholds** | ML optimizes rule thresholds | Auto-tuning | ❌ P2 |

**Specification**:

**1. ML Scores as Rule Conditions**:
```yaml
# Example SIGMA rule with ML condition
detection:
  selection:
    event_type: file_access
    file_path|contains: '\sensitive\'
  ml_condition:
    model: "file_access_anomaly"
    score: ">0.7" # Anomaly score > 0.7
  condition: selection AND ml_condition
```

**Implementation Needed**:
```go
// In detect/engine.go
func (e *RuleEngine) evaluateRule(event *core.Event, rule *core.Rule) bool {
    // Standard condition evaluation
    if !e.evaluateSelection(event, rule.Selection) {
        return false
    }

    // NEW: ML condition evaluation
    if rule.MLCondition != nil {
        mlResult, err := e.mlDetector.Detect(ctx, event)
        if err != nil {
            e.logger.Warnf("ML evaluation failed for rule %s: %v", rule.ID, err)
            return false // Fail-safe: don't match if ML unavailable
        }

        // Check ML threshold
        if !evaluateMLCondition(mlResult, rule.MLCondition) {
            return false
        }
    }

    return true
}

type MLCondition struct {
    ModelID   string  // Which ML model to use
    Operator  string  // ">", ">=", "<", "<=", "=="
    Threshold float64 // Anomaly score threshold
}
```

**2. Rule Recommendation from ML Patterns**:
```go
// Auto-generate rule suggestions from detected patterns
type RuleSuggestion struct {
    SuggestedRuleName string
    Confidence        float64
    DetectionPattern  map[string]interface{} // Field patterns
    AlertFrequency    int // How often ML detected this pattern
    ExampleEvents     []string // Event IDs

    GeneratedRule     *core.Rule // Auto-generated rule
}

// Example: If ML repeatedly detects anomalies with same field combination
// → Suggest creating a rule for that pattern
func (rg *RuleRecommender) AnalyzeMLPatterns(mlAlerts []*Alert) []*RuleSuggestion {
    // Group alerts by common features
    patterns := groupByCommonFeatures(mlAlerts)

    suggestions := []*RuleSuggestion{}
    for pattern, alerts := range patterns {
        if len(alerts) >= 10 { // Pattern seen 10+ times
            suggestion := &RuleSuggestion{
                SuggestedRuleName: fmt.Sprintf("ML-Generated: %s", pattern.Name),
                Confidence:        calculateConfidence(alerts),
                DetectionPattern:  pattern.Fields,
                AlertFrequency:    len(alerts),
                ExampleEvents:     getEventIDs(alerts[:5]),
            }

            // Auto-generate rule
            suggestion.GeneratedRule = generateRule(pattern)
            suggestions = append(suggestions, suggestion)
        }
    }

    return suggestions
}
```

**Current Implementation**:
```go
// main.go:230-253 - Sequential processing
go func() {
    for event := range eventChan {
        // Rule-based detection first
        results := ruleEngine.Evaluate(event)
        if len(results) > 0 {
            // Create alerts for rule matches
            for _, result := range results {
                // ...
            }
        }

        // ML-based detection second (separate)
        if config.ML.Enabled {
            mlResult, err := mlSystem.DetectAnomaly(event)
            if err == nil && mlResult.IsAnomaly {
                // Create ML alert
                // ...
            }
        }
    }
}()
```

**Gaps**:
- ❌ No ML scores in rule conditions
- ❌ No rule recommendation engine
- ❌ No ML-assisted threshold tuning
- ✅ Sequential processing works

**Acceptance Criteria**:
- [ ] SIGMA rules support `ml_condition` field
- [ ] ML scores accessible during rule evaluation
- [ ] Rule recommendation API generates suggestions
- [ ] Auto-generated rules validated before deployment
- [ ] ML-assisted threshold tuning reduces FP by 20%
- [ ] Hybrid detection performance <100ms per event

**Test Requirements**:
```go
// TEST-ML-016: ML condition in rules
func TestHybridDetection_MLCondition(t *testing.T) {
    rule := &core.Rule{
        ID:   "hybrid-001",
        Name: "Suspicious File Access with ML Anomaly",
        Selection: map[string]interface{}{
            "event_type": "file_access",
            "file_path":  "*\\sensitive\\*",
        },
        MLCondition: &MLCondition{
            ModelID:   "file_access_anomaly",
            Operator:  ">",
            Threshold: 0.7,
        },
    }

    engine := NewRuleEngine([]*core.Rule{rule}, mlDetector, 0)

    // Event matches selection but ML score low
    event1 := &core.Event{
        Fields: map[string]interface{}{
            "event_type": "file_access",
            "file_path":  "C:\\sensitive\\file.txt",
        },
    }
    // Mock ML detector returns score 0.5
    mockMLDetector.SetScore(0.5)

    matches := engine.Evaluate(event1)
    assert.Empty(t, matches, "Rule should not match (ML score too low)")

    // Event matches selection AND ML score high
    event2 := &core.Event{
        Fields: map[string]interface{}{
            "event_type": "file_access",
            "file_path":  "C:\\sensitive\\secret.doc",
        },
    }
    // Mock ML detector returns score 0.9
    mockMLDetector.SetScore(0.9)

    matches = engine.Evaluate(event2)
    assert.Len(t, matches, 1, "Rule should match (ML score above threshold)")
}

// TEST-ML-017: Rule recommendation from ML patterns
func TestRuleRecommender_GenerateSuggestions(t *testing.T) {
    recommender := NewRuleRecommender(mlAlertStorage)

    // Simulate 15 ML alerts with same pattern
    for i := 0; i < 15; i++ {
        alert := &Alert{
            EventFields: map[string]interface{}{
                "process_name": "powershell.exe",
                "command_line": "*-EncodedCommand*",
            },
            MLScore: 0.85,
        }
        mlAlertStorage.Store(alert)
    }

    // Generate suggestions
    suggestions := recommender.AnalyzeMLPatterns()

    require.NotEmpty(t, suggestions)
    suggestion := suggestions[0]
    assert.Contains(t, suggestion.SuggestedRuleName, "powershell.exe")
    assert.GreaterOrEqual(t, suggestion.AlertFrequency, 10)
    assert.NotNil(t, suggestion.GeneratedRule)

    // Verify generated rule structure
    generatedRule := suggestion.GeneratedRule
    assert.Contains(t, generatedRule.Selection, "process_name")
    assert.Contains(t, generatedRule.Selection, "command_line")
}
```

**TBDs**:
- [ ] **TBD-ML-016**: Rule recommendation confidence threshold (default: 0.8?) (Owner: Detection Team, Deadline: Week 4)
- [ ] **TBD-ML-017**: Minimum pattern frequency for rule suggestion (10 alerts?) (Owner: Detection Team, Deadline: Week 4)

---

## 3. Non-Functional Requirements

### 3.1 Performance

#### NFR-ML-001: Real-Time Anomaly Detection Latency

**Priority**: P0 (Critical)
**Requirement**: ML anomaly detection MUST complete within 100ms (p95) per event.

**Rationale**: Detection latency impacts alert generation time and analyst response.

**Current Performance**: TBD - No benchmarks performed

**Measurement**: `time(feature_extraction) + time(detection) + time(alert_generation)`

**Acceptance Criteria**:
- [ ] Feature extraction <30ms (p95)
- [ ] Model inference <50ms (p95)
- [ ] Alert generation <20ms (p95)
- [ ] Total latency <100ms (p95)

**Optimization Strategies**:
1. Feature caching (Redis) - ✅ Implemented
2. Model result caching
3. Batch processing (trade latency for throughput)
4. GPU acceleration (future)

**Test Requirements**:
```go
// TEST-ML-018: Anomaly detection latency
func TestPerformance_AnomalyDetectionLatency(t *testing.T) {
    if testing.Short() {
        t.Skip("Performance test requires -short=false")
    }

    detector := setupProductionDetector(t)
    event := generateRealisticEvent()

    // Warm-up
    for i := 0; i < 100; i++ {
        detector.Detect(ctx, event)
    }

    // Measure p95 latency
    latencies := make([]time.Duration, 1000)
    for i := 0; i < 1000; i++ {
        start := time.Now()
        _, err := detector.Detect(ctx, event)
        require.NoError(t, err)
        latencies[i] = time.Since(start)
    }

    sort.Slice(latencies, func(i, j int) bool {
        return latencies[i] < latencies[j]
    })

    p95 := latencies[950] // 95th percentile
    assert.Less(t, p95, 100*time.Millisecond, "p95 latency exceeds 100ms SLA")

    t.Logf("Latency stats: p50=%v, p95=%v, p99=%v", latencies[500], latencies[950], latencies[990])
}
```

---

#### NFR-ML-002: Training Performance

**Priority**: P1 (High)
**Requirement**: Model training MUST complete within 1 hour for 1 million events.

**Rationale**: Fast training enables frequent model updates and rapid experimentation.

**Acceptance Criteria**:
- [ ] Training throughput ≥280 events/second
- [ ] Training completes in <60 minutes for 1M events
- [ ] Training can be cancelled gracefully (context.Done)
- [ ] Training progress trackable (% complete)

---

#### NFR-ML-003: Scalability

**Priority**: P1 (High)
**Requirement**: ML system MUST handle 10,000 events/second sustained load.

**Acceptance Criteria**:
- [ ] Feature extraction keeps pace with 10K EPS
- [ ] Detection doesn't create backpressure
- [ ] Training runs in background without impacting detection
- [ ] Memory usage bounded (no leaks)

---

### 3.2 Resource Management

#### NFR-ML-004: Memory Limits

**Priority**: P0 (Critical)
**Requirement**: ML system MUST stay within 2GB RAM for typical deployment.

**Acceptance Criteria**:
- [ ] Feature cache limited to 10,000 entries (configurable)
- [ ] Training data batch size limited (configurable)
- [ ] Model count limited (max 10 active models)
- [ ] Memory leak testing performed

---

#### NFR-ML-005: CPU Utilization

**Priority**: P1 (High)
**Requirement**: ML training MUST NOT exceed 50% CPU utilization during normal operations.

**Acceptance Criteria**:
- [ ] Training runs at reduced priority (background)
- [ ] Detection prioritized over training
- [ ] CPU throttling configurable

---

### 3.3 Reliability

#### NFR-ML-006: Model Availability

**Priority**: P0 (Critical)
**Requirement**: ML models MUST survive system restarts without data loss.

**Acceptance Criteria**:
- [ ] Models serialized to disk/database
- [ ] Models loaded automatically on startup
- [ ] Model training state recoverable after crash
- [ ] Graceful degradation if ML unavailable (rules continue)

---

#### NFR-ML-007: Fault Tolerance

**Priority**: P0 (Critical)
**Requirement**: ML failures MUST NOT impact rule-based detection.

**Acceptance Criteria**:
- [x] ML errors logged but don't crash system
- [x] Events processed even if ML fails
- [x] ML detector optional (can be disabled)
- [ ] Circuit breaker for repeated ML failures

---

## 4. Data Models

### 4.1 Model Metadata Schema

```go
type MLModel struct {
    ID              string                 `json:"id" bson:"_id"`
    Name            string                 `json:"name" bson:"name"`
    Algorithm       string                 `json:"algorithm" bson:"algorithm"`
    Version         string                 `json:"version" bson:"version"`
    Status          ModelStatus            `json:"status" bson:"status"`

    CreatedAt       time.Time              `json:"created_at" bson:"created_at"`
    TrainedAt       *time.Time             `json:"trained_at,omitempty" bson:"trained_at,omitempty"`
    DeployedAt      *time.Time             `json:"deployed_at,omitempty" bson:"deployed_at,omitempty"`
    RetiredAt       *time.Time             `json:"retired_at,omitempty" bson:"retired_at,omitempty"`

    Config          map[string]interface{} `json:"config" bson:"config"`
    FeatureList     []string               `json:"feature_list" bson:"feature_list"`

    TrainingMetrics *TrainingMetrics       `json:"training_metrics,omitempty" bson:"training_metrics,omitempty"`
    Performance     *ModelPerformance      `json:"performance,omitempty" bson:"performance,omitempty"`

    ArtifactPath    string                 `json:"artifact_path" bson:"artifact_path"`
}

type ModelStatus string

const (
    ModelStatusCreated    ModelStatus = "created"
    ModelStatusTraining   ModelStatus = "training"
    ModelStatusValidating ModelStatus = "validating"
    ModelStatusDeployed   ModelStatus = "deployed"
    ModelStatusDeprecated ModelStatus = "deprecated"
    ModelStatusFailed     ModelStatus = "failed"
)

type TrainingMetrics struct {
    SampleCount      int64         `json:"sample_count"`
    TrainingDuration time.Duration `json:"training_duration"`
    ConvergenceScore float64       `json:"convergence_score,omitempty"`
}

type ModelPerformance struct {
    Precision         float64            `json:"precision"`
    Recall            float64            `json:"recall"`
    F1Score           float64            `json:"f1_score"`
    FalsePositiveRate float64            `json:"false_positive_rate"`
    AUCROC            float64            `json:"auc_roc,omitempty"`
    LastUpdated       time.Time          `json:"last_updated"`
}
```

---

## 5. API Specification

### 5.1 Model Management APIs

#### POST /api/v1/ml/models
Create a new ML model.

**Request**:
```json
{
  "name": "Network Anomaly Detector",
  "algorithm": "isolation_forest",
  "config": {
    "num_trees": 100,
    "contamination": 0.1
  },
  "feature_list": ["bytes_sent", "bytes_received", "duration"]
}
```

**Response**: `201 Created`
```json
{
  "id": "model-12345",
  "status": "created"
}
```

---

#### POST /api/v1/ml/models/{id}/train
Trigger model training.

**Request**:
```json
{
  "dataset_id": "dataset-67890",
  "training_params": {
    "batch_size": 1000,
    "validation_ratio": 0.2
  }
}
```

**Response**: `202 Accepted`

---

#### GET /api/v1/ml/models/{id}
Get model details.

**Response**: `200 OK`
```json
{
  "id": "model-12345",
  "name": "Network Anomaly Detector",
  "algorithm": "isolation_forest",
  "status": "deployed",
  "performance": {
    "precision": 0.85,
    "recall": 0.78,
    "f1_score": 0.81
  }
}
```

---

#### GET /api/v1/ml/models/{id}/metrics
Get model performance metrics over time.

**Query Params**:
- `start`: Start timestamp
- `end`: End timestamp
- `interval`: Aggregation interval (1h, 1d, 7d)

**Response**: `200 OK`
```json
{
  "metrics": [
    {
      "timestamp": "2025-01-16T12:00:00Z",
      "precision": 0.85,
      "recall": 0.78,
      "false_positive_rate": 0.02,
      "predictions": 150
    }
  ]
}
```

---

## 6. Security Requirements

### SEC-ML-001: Model Tampering Prevention

**Requirement**: ML models MUST be protected from unauthorized modification.

**Controls**:
- Model files stored with restrictive permissions (0600)
- Model integrity verified with checksums
- Model updates logged in audit trail
- Role-based access control for model management

---

### SEC-ML-002: Adversarial Input Detection

**Requirement**: ML system SHOULD detect adversarial inputs designed to evade detection.

**Controls**:
- Input validation (feature value ranges)
- Anomaly detection on features themselves
- Rate limiting on ML API
- Logging suspicious feature patterns

**TBD**: Adversarial robustness testing framework (Owner: Security Team, Deadline: Week 6)

---

## 7. Testing Requirements

### 7.1 Unit Tests

**Coverage Target**: ≥85% for ML components

**Critical Test Cases**:
- [x] Z-Score anomaly detection
- [x] IQR outlier detection
- [x] Isolation Forest training and detection
- [x] Feature extraction from events
- [x] Feature normalization
- [x] Ensemble voting logic
- [ ] Model persistence (save/load)
- [ ] Performance metric calculation
- [ ] Drift detection

---

### 7.2 Integration Tests

**Test Scenarios**:
- [ ] End-to-end: Event → Feature Extraction → Detection → Alert
- [ ] Training pipeline with real event data
- [ ] Model deployment and rollback
- [ ] ML + Rule hybrid detection
- [ ] Feature caching (Redis)

---

### 7.3 Performance Tests

**Benchmarks Required**:
- [ ] Anomaly detection latency (p50, p95, p99)
- [ ] Training throughput (events/sec)
- [ ] Feature extraction latency
- [ ] Model inference latency (per algorithm)
- [ ] Memory usage under load

---

## 8. TBD Tracker

| ID | Description | Owner | Deadline | Priority | Status |
|----|-------------|-------|----------|----------|--------|
| TBD-ML-001 | Optimal Z-score window size | ML Team | Week 3 | P1 | OPEN |
| TBD-ML-002 | Seasonal pattern handling | ML Team | Week 4 | P2 | OPEN |
| TBD-ML-003 | Isolation Forest tree count optimization | ML Team | Week 3 | P1 | OPEN |
| TBD-ML-004 | Feature importance calculation method | ML Team | Week 4 | P1 | OPEN |
| TBD-ML-005 | Model storage backend | Architecture Team | Week 2 | P0 | OPEN |
| TBD-ML-006 | Model serialization format | ML Team | Week 2 | P0 | OPEN |
| TBD-ML-007 | Maximum model versions retained | ML Team | Week 3 | P1 | OPEN |
| TBD-ML-008 | Analyst feedback mechanism | UX Team | Week 3 | P0 | OPEN |
| TBD-ML-009 | Drift detection threshold | ML Team | Week 3 | P0 | OPEN |
| TBD-ML-010 | Metric aggregation window | ML Team | Week 3 | P1 | OPEN |
| TBD-ML-011 | Default training data time range | ML Team | Week 2 | P1 | OPEN |
| TBD-ML-012 | Maximum dataset size | ML Team | Week 2 | P1 | OPEN |
| TBD-ML-013 | Dataset storage format | ML Team | Week 3 | P2 | OPEN |
| TBD-ML-014 | Explainability library selection | ML Team | Week 4 | P1 | OPEN |
| TBD-ML-015 | Explanation template system | UX Team | Week 4 | P1 | OPEN |
| TBD-ML-016 | Rule recommendation confidence threshold | Detection Team | Week 4 | P2 | OPEN |
| TBD-ML-017 | Minimum pattern frequency for rule suggestion | Detection Team | Week 4 | P2 | OPEN |

---

## 9. Compliance Verification Checklist

### Core Functionality
- [x] Statistical anomaly detection (Z-Score, IQR)
- [x] Isolation Forest anomaly detection
- [x] Feature extraction and normalization
- [x] Ensemble detection with voting
- [ ] Model persistence across restarts
- [ ] Model versioning and rollback
- [ ] Performance metric tracking
- [ ] Drift detection and alerting

### Alert Generation
- [x] ML alerts generated from anomalies
- [ ] Explainability (top contributing features)
- [ ] Human-readable explanations
- [ ] Recommended actions
- [ ] Confidence scoring

### Integration
- [x] Sequential ML + Rule detection
- [ ] ML scores in rule conditions
- [ ] Rule recommendation from ML patterns
- [ ] ML-assisted threshold tuning

### Performance
- [ ] Detection latency <100ms (p95)
- [ ] Training completes in <1 hour (1M events)
- [ ] Handles 10K EPS sustained
- [ ] Memory usage <2GB
- [ ] CPU usage <50% during training

### Security
- [ ] Model tampering prevention
- [ ] Adversarial input detection
- [ ] Access control for model management
- [ ] Audit logging for model changes

---

## 10. References

### Academic Papers
1. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). "Isolation Forest" - IEEE ICDM
2. Chandola, V., Banerjee, A., & Kumar, V. (2009). "Anomaly Detection: A Survey" - ACM Computing Surveys
3. Lundberg, S. M., & Lee, S. I. (2017). "A Unified Approach to Interpreting Model Predictions" (SHAP) - NeurIPS

### Industry Standards
- NIST AI Risk Management Framework (NIST AI RMF)
- OWASP Machine Learning Security Top 10
- Gartner UEBA Market Guide

### Internal Documents
- `docs/requirements/alert-requirements.md`
- `docs/requirements/correlation-rule-requirements.md`
- `docs/requirements/performance-requirements.md`
- `docs/requirements/security-threat-model.md`

### Related Code
- `ml/system.go`: Core ML orchestration
- `ml/*_detector.go`: Anomaly detection algorithms
- `ml/feature_extractor.go`: Feature engineering
- `ml/training_pipeline.go`: Training pipeline
- `api/ml_*.go`: ML API endpoints

---

## 11. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-16 | Blueprint Architect | Initial comprehensive ML requirements document |

---

**Document Status**: DRAFT - Pending ML Team Review
**Next Review Date**: 2025-11-23
**Approvers**: ML Team Lead, Detection Engineering Lead, Architect
**Classification**: INTERNAL

---

**End of Machine Learning Requirements Document**
