package ml

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestEnsembleEngine_VotingStrategies tests different voting strategies
func TestEnsembleEngine_VotingStrategies(t *testing.T) {
	tests := []struct {
		name           string
		votingStrategy string
		wantVotingUsed string
	}{
		{
			name:           "majority voting",
			votingStrategy: "majority",
			wantVotingUsed: "majority",
		},
		{
			name:           "weighted voting",
			votingStrategy: "weighted",
			wantVotingUsed: "weighted",
		},
		{
			name:           "average voting",
			votingStrategy: "average",
			wantVotingUsed: "average",
		},
		{
			name:           "minimum voting",
			votingStrategy: "minimum",
			wantVotingUsed: "minimum",
		},
		{
			name:           "unknown defaults to weighted",
			votingStrategy: "unknown",
			wantVotingUsed: "weighted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				Algorithms:     []string{"zscore", "iqr"},
				VotingStrategy: tt.votingStrategy,
				Logger:         logger,
			}

			ensemble := NewEnsembleEngine(config)
			require.NotNil(t, ensemble)

			ctx := context.Background()

			// Train detectors
			for i := 0; i < 50; i++ {
				event := createTestEvent("train", time.Now())
				features, _ := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger}).ExtractFeatures(ctx, event)
				ensemble.Train(ctx, features)
			}

			// Test detection
			testEvent := createTestEvent("test", time.Now())
			features, _ := NewFeatureExtractorManager(&FeatureExtractorConfig{Logger: logger}).ExtractFeatures(ctx, testEvent)
			result, err := ensemble.Detect(ctx, features)

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Score, 0.0)
			assert.LessOrEqual(t, result.Score, 1.0)
		})
	}
}

// TestEnsembleEngine_AddRemoveDetector tests adding and removing detectors
func TestEnsembleEngine_AddRemoveDetector(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	}

	ensemble := NewEnsembleEngine(config)

	// Add a new detector
	newDetector := NewIQRDetector(&IQRConfig{Logger: logger})
	err := ensemble.AddDetector("iqr", newDetector, 1.5)
	require.NoError(t, err)

	// Verify it was added
	detectors := ensemble.GetDetectors()
	assert.Equal(t, 2, len(detectors))
	assert.NotNil(t, detectors["iqr"])

	// Try to add duplicate
	err = ensemble.AddDetector("iqr", newDetector, 1.5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Remove detector
	err = ensemble.RemoveDetector("iqr")
	require.NoError(t, err)

	// Verify it was removed
	detectors = ensemble.GetDetectors()
	assert.Equal(t, 1, len(detectors))

	// Try to remove non-existent detector
	err = ensemble.RemoveDetector("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestEnsembleEngine_GetTopAnomalies tests retrieving top anomalies
func TestEnsembleEngine_GetTopAnomalies(t *testing.T) {
	logger := zap.NewNop().Sugar()
	config := &EnsembleEngineConfig{
		Algorithms: []string{"zscore"},
		Logger:     logger,
	}

	ensemble := NewEnsembleEngine(config)

	// Create some results
	results := map[string]*AnomalyResult{
		"zscore": {
			IsAnomaly:  true,
			Score:      0.8,
			Confidence: 0.9,
		},
	}

	topAnomalies := ensemble.GetTopAnomalies(results, 5)

	// Currently returns empty slice (placeholder implementation)
	assert.NotNil(t, topAnomalies)
	assert.Equal(t, 0, len(topAnomalies))
}

// TestEnsembleResult_GetScore tests score retrieval
func TestEnsembleResult_GetScore(t *testing.T) {
	result := &EnsembleResult{
		Score: 0.75,
	}

	assert.Equal(t, 0.75, result.GetScore())
}

// TestEnsembleResult_GetIsAnomaly tests anomaly status retrieval
func TestEnsembleResult_GetIsAnomaly(t *testing.T) {
	tests := []struct {
		name      string
		isAnomaly bool
	}{
		{"is anomaly", true},
		{"is not anomaly", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &EnsembleResult{
				IsAnomaly: tt.isAnomaly,
			}

			assert.Equal(t, tt.isAnomaly, result.GetIsAnomaly())
		})
	}
}

// TestEnsembleEngine_MajorityVote tests majority voting logic
func TestEnsembleEngine_MajorityVote(t *testing.T) {
	tests := []struct {
		name          string
		results       map[string]*AnomalyResult
		anomalyVotes  int
		wantIsAnomaly bool
	}{
		{
			name: "majority anomaly",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: true, Score: 0.9, Confidence: 0.9},
				"detector2": {IsAnomaly: true, Score: 0.8, Confidence: 0.8},
				"detector3": {IsAnomaly: false, Score: 0.3, Confidence: 0.7},
			},
			anomalyVotes:  2,
			wantIsAnomaly: true,
		},
		{
			name: "majority normal",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: false, Score: 0.2, Confidence: 0.9},
				"detector2": {IsAnomaly: false, Score: 0.1, Confidence: 0.8},
				"detector3": {IsAnomaly: true, Score: 0.7, Confidence: 0.6},
			},
			anomalyVotes:  1,
			wantIsAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				VotingStrategy: "majority",
				Logger:         logger,
			}
			ensemble := NewEnsembleEngine(config)

			isAnomaly, score, confidence := ensemble.majorityVote(tt.results, tt.anomalyVotes)

			assert.Equal(t, tt.wantIsAnomaly, isAnomaly)
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 1.0)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
		})
	}
}

// TestEnsembleEngine_AverageVote tests average voting logic
func TestEnsembleEngine_AverageVote(t *testing.T) {
	tests := []struct {
		name          string
		results       map[string]*AnomalyResult
		wantIsAnomaly bool
	}{
		{
			name: "high average score",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: true, Score: 0.9, Confidence: 0.9},
				"detector2": {IsAnomaly: true, Score: 0.8, Confidence: 0.8},
			},
			wantIsAnomaly: true, // Average 0.85 > 0.5
		},
		{
			name: "low average score",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: false, Score: 0.2, Confidence: 0.9},
				"detector2": {IsAnomaly: false, Score: 0.3, Confidence: 0.8},
			},
			wantIsAnomaly: false, // Average 0.25 < 0.5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				VotingStrategy: "average",
				Logger:         logger,
			}
			ensemble := NewEnsembleEngine(config)

			isAnomaly, score, confidence := ensemble.averageVote(tt.results)

			assert.Equal(t, tt.wantIsAnomaly, isAnomaly)
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 1.0)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
		})
	}
}

// TestEnsembleEngine_MinimumVote tests minimum (conservative) voting logic
func TestEnsembleEngine_MinimumVote(t *testing.T) {
	tests := []struct {
		name          string
		results       map[string]*AnomalyResult
		wantIsAnomaly bool
	}{
		{
			name: "all agree anomaly",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: true, Score: 0.9, Confidence: 0.9},
				"detector2": {IsAnomaly: true, Score: 0.8, Confidence: 0.8},
			},
			wantIsAnomaly: true,
		},
		{
			name: "not all agree",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: true, Score: 0.9, Confidence: 0.9},
				"detector2": {IsAnomaly: false, Score: 0.3, Confidence: 0.8},
			},
			wantIsAnomaly: false,
		},
		{
			name: "all agree normal",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: false, Score: 0.2, Confidence: 0.9},
				"detector2": {IsAnomaly: false, Score: 0.1, Confidence: 0.8},
			},
			wantIsAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				VotingStrategy: "minimum",
				Logger:         logger,
			}
			ensemble := NewEnsembleEngine(config)

			isAnomaly, score, confidence := ensemble.minimumVote(tt.results)

			assert.Equal(t, tt.wantIsAnomaly, isAnomaly)
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 1.0)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
		})
	}
}

// TestEnsembleEngine_WeightedVote tests weighted voting logic
func TestEnsembleEngine_WeightedVote(t *testing.T) {
	tests := []struct {
		name          string
		results       map[string]*AnomalyResult
		weights       map[string]float64
		weightedScore float64
		totalWeight   float64
		wantIsAnomaly bool
	}{
		{
			name: "weighted high score",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: true, Score: 0.9, Confidence: 0.9},
				"detector2": {IsAnomaly: true, Score: 0.8, Confidence: 0.8},
			},
			weights: map[string]float64{
				"detector1": 2.0,
				"detector2": 1.0,
			},
			weightedScore: 2.6, // (0.9*2.0 + 0.8*1.0)
			totalWeight:   3.0,
			wantIsAnomaly: true, // 2.6/3.0 = 0.87 > 0.5
		},
		{
			name: "weighted low score",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: false, Score: 0.2, Confidence: 0.9},
				"detector2": {IsAnomaly: false, Score: 0.3, Confidence: 0.8},
			},
			weights: map[string]float64{
				"detector1": 1.0,
				"detector2": 1.0,
			},
			weightedScore: 0.5, // (0.2*1.0 + 0.3*1.0)
			totalWeight:   2.0,
			wantIsAnomaly: false, // 0.5/2.0 = 0.25 < 0.5
		},
		{
			name: "zero total weight fallback",
			results: map[string]*AnomalyResult{
				"detector1": {IsAnomaly: false, Score: 0.2, Confidence: 0.9},
			},
			weights: map[string]float64{
				"detector1": 0.0,
			},
			weightedScore: 0.0,
			totalWeight:   0.0,
			wantIsAnomaly: false, // Falls back to majority vote
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				VotingStrategy: "weighted",
				Weights:        tt.weights,
				Logger:         logger,
			}
			ensemble := NewEnsembleEngine(config)

			isAnomaly, score, confidence := ensemble.weightedVote(tt.results, tt.weightedScore, tt.totalWeight)

			assert.Equal(t, tt.wantIsAnomaly, isAnomaly)
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 1.0)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
		})
	}
}

// TestEnsembleEngine_ApplyVotingStrategy tests strategy application
func TestEnsembleEngine_ApplyVotingStrategy(t *testing.T) {
	results := map[string]*AnomalyResult{
		"detector1": {IsAnomaly: true, Score: 0.9, Confidence: 0.9},
		"detector2": {IsAnomaly: true, Score: 0.8, Confidence: 0.8},
	}

	strategies := []string{"majority", "weighted", "average", "minimum", "unknown"}

	for _, strategy := range strategies {
		t.Run(strategy, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				VotingStrategy: strategy,
				Weights: map[string]float64{
					"detector1": 1.0,
					"detector2": 1.0,
				},
				Logger: logger,
			}
			ensemble := NewEnsembleEngine(config)

			isAnomaly, score, confidence := ensemble.applyVotingStrategy(results, 2, 1.7, 2.0)

			// All strategies should return valid results
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 1.0)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
			// Type assertion to verify it's a boolean
			_ = isAnomaly
		})
	}
}

// TestEnsembleEngine_DefaultConfig tests default configuration
func TestEnsembleEngine_DefaultConfig(t *testing.T) {
	ensemble := NewEnsembleEngine(nil)

	require.NotNil(t, ensemble)
	assert.Equal(t, 3, len(ensemble.config.Algorithms)) // zscore, iqr, isolation_forest
	assert.Equal(t, "weighted", ensemble.config.VotingStrategy)
	assert.Equal(t, 0.6, ensemble.config.MinConfidence)
	assert.NotNil(t, ensemble.config.Weights)
	assert.NotNil(t, ensemble.config.Logger)
}

// TestEnsembleEngine_CustomWeights tests custom algorithm weights
func TestEnsembleEngine_CustomWeights(t *testing.T) {
	logger := zap.NewNop().Sugar()
	customWeights := map[string]float64{
		"zscore": 2.0,
		"iqr":    1.5,
	}

	config := &EnsembleEngineConfig{
		Algorithms:     []string{"zscore", "iqr"},
		Weights:        customWeights,
		VotingStrategy: "weighted",
		Logger:         logger,
	}

	ensemble := NewEnsembleEngine(config)

	assert.Equal(t, 2.0, ensemble.config.Weights["zscore"])
	assert.Equal(t, 1.5, ensemble.config.Weights["iqr"])
}

// TestEnsembleEngine_InitializeDetectors tests detector initialization
func TestEnsembleEngine_InitializeDetectors(t *testing.T) {
	tests := []struct {
		name       string
		algorithms []string
		wantCount  int
	}{
		{
			name:       "all standard algorithms",
			algorithms: []string{"zscore", "iqr", "isolation_forest"},
			wantCount:  3,
		},
		{
			name:       "subset of algorithms",
			algorithms: []string{"zscore"},
			wantCount:  1,
		},
		{
			name:       "with unknown algorithm",
			algorithms: []string{"zscore", "unknown", "iqr"},
			wantCount:  2, // Only zscore and iqr are created
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop().Sugar()
			config := &EnsembleEngineConfig{
				Algorithms: tt.algorithms,
				Logger:     logger,
			}

			ensemble := NewEnsembleEngine(config)

			detectors := ensemble.GetDetectors()
			assert.Equal(t, tt.wantCount, len(detectors))
		})
	}
}
