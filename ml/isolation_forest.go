package ml

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"go.uber.org/zap"
)

// IsolationTree represents a single isolation tree in the forest
type IsolationTree struct {
	root   *IsolationNode
	height int
}

// IsolationNode represents a node in the isolation tree
type IsolationNode struct {
	left    *IsolationNode
	right   *IsolationNode
	feature string  // Feature name used for split
	value   float64 // Split value
	size    int     // Number of samples in this subtree
	isLeaf  bool    // Whether this is a leaf node
}

// IsolationForestConfig holds configuration for Isolation Forest
type IsolationForestConfig struct {
	NumTrees      int     // Number of trees in the forest (default: 100)
	SubsampleSize int     // Size of subsample for each tree (default: 256)
	MaxDepth      int     // Maximum depth of each tree (default: 8)
	Contamination float64 // Expected proportion of anomalies (default: 0.1)
	Logger        *zap.SugaredLogger
}

// IsolationForest implements Isolation Forest anomaly detection
type IsolationForest struct {
	trees        []*IsolationTree
	config       *IsolationForestConfig
	features     []string // Feature names used for training
	logger       *zap.SugaredLogger
	stats        DetectorStats
	isTrained    bool
	trainingData []*FeatureVector // Accumulated training data for batch training
}

// NewIsolationForest creates a new Isolation Forest detector
func NewIsolationForest(config *IsolationForestConfig) *IsolationForest {
	if config == nil {
		config = &IsolationForestConfig{}
	}

	if config.NumTrees == 0 {
		config.NumTrees = 100
	}
	if config.SubsampleSize == 0 {
		config.SubsampleSize = 256
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = 8
	}
	if config.Contamination == 0 {
		config.Contamination = 0.1
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop().Sugar()
	}

	return &IsolationForest{
		trees:  make([]*IsolationTree, 0, config.NumTrees),
		config: config,
		logger: config.Logger,
		stats:  DetectorStats{},
	}
}

// Name returns the detector name
func (f *IsolationForest) Name() string {
	return "isolation_forest"
}

// Train accumulates training data and rebuilds forest when needed
func (f *IsolationForest) Train(ctx context.Context, features *FeatureVector) error {
	if features == nil || features.Features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	start := time.Now()
	defer func() {
		f.stats.TrainingTime += time.Since(start)
		f.stats.LastUpdated = time.Now()
	}()

	// Extract feature names from first training sample
	if len(f.features) == 0 {
		f.features = make([]string, 0, len(features.Features))
		for name := range features.Features {
			f.features = append(f.features, name)
		}
		sort.Strings(f.features) // Ensure consistent ordering
	}

	// Accumulate training data instead of rebuilding immediately
	f.trainingData = append(f.trainingData, features)
	f.stats.TotalSamples++

	// Rebuild forest with accumulated data
	// This is more efficient than rebuilding for each sample
	// The forest will use subsampling, so large training sets don't increase complexity
	f.buildForest(f.trainingData)
	f.isTrained = true

	return nil
}

// Detect analyzes features and returns anomaly result
func (f *IsolationForest) Detect(ctx context.Context, features *FeatureVector) (*AnomalyResult, error) {
	if features == nil || features.Features == nil {
		return nil, fmt.Errorf("features cannot be nil")
	}

	if !f.isTrained {
		return nil, fmt.Errorf("forest not trained yet")
	}

	start := time.Now()
	defer func() {
		detectionTime := time.Since(start)
		if f.stats.DetectionTimeAvg == 0 {
			f.stats.DetectionTimeAvg = detectionTime
		} else {
			f.stats.DetectionTimeAvg = (f.stats.DetectionTimeAvg + detectionTime) / 2
		}
	}()

	// Calculate average path length across all trees
	totalScore := 0.0
	validTrees := 0

	for _, tree := range f.trees {
		if tree != nil {
			pathLength := f.pathLength(tree.root, features, 0)
			score := f.anomalyScore(pathLength, f.config.SubsampleSize)
			totalScore += score
			validTrees++
		}
	}

	if validTrees == 0 {
		return nil, fmt.Errorf("no valid trees in forest")
	}

	avgScore := totalScore / float64(validTrees)

	// Convert score to anomaly decision
	// Scores closer to 1 are more anomalous
	isAnomaly := avgScore > 0.5 // Simple threshold, could be made configurable

	// Calculate confidence based on score deviation from expected normal range
	confidence := math.Min(avgScore*2.0, 1.0) // Scale to 0-1

	result := &AnomalyResult{
		IsAnomaly:  isAnomaly,
		Score:      avgScore,
		Confidence: confidence,
		Threshold:  0.5, // Simple threshold for now
		Algorithm:  f.Name(),
		DetectedAt: time.Now(),
	}

	if isAnomaly {
		f.stats.AnomaliesFound++
	}

	return result, nil
}

// GetStats returns detector statistics
func (f *IsolationForest) GetStats() DetectorStats {
	return f.stats
}

// Reset clears all learned patterns
func (f *IsolationForest) Reset() {
	f.trees = make([]*IsolationTree, 0, f.config.NumTrees)
	f.features = nil
	f.stats = DetectorStats{}
	f.isTrained = false
}

// buildForest constructs the isolation forest
func (f *IsolationForest) buildForest(trainingData []*FeatureVector) {
	f.trees = make([]*IsolationTree, 0, f.config.NumTrees)

	for i := 0; i < f.config.NumTrees; i++ {
		// Subsample the training data
		subsample := f.subsample(trainingData, f.config.SubsampleSize)

		// Build isolation tree
		tree := f.buildTree(subsample, 0)
		f.trees = append(f.trees, tree)
	}
}

// subsample randomly selects a subset of training data
func (f *IsolationForest) subsample(data []*FeatureVector, size int) []*FeatureVector {
	if len(data) <= size {
		return data
	}

	result := make([]*FeatureVector, size)
	for i := 0; i < size; i++ {
		result[i] = data[rand.Intn(len(data))]
	}

	return result
}

// buildTree recursively builds an isolation tree
func (f *IsolationForest) buildTree(data []*FeatureVector, depth int) *IsolationTree {
	if len(data) <= 1 || depth >= f.config.MaxDepth {
		// Create leaf node
		return &IsolationTree{
			root: &IsolationNode{
				size:   len(data),
				isLeaf: true,
			},
			height: depth,
		}
	}

	// Randomly select a feature
	featureIdx := rand.Intn(len(f.features))
	featureName := f.features[featureIdx]

	// Find min and max values for this feature
	minVal, maxVal := f.findMinMax(data, featureName)

	if minVal == maxVal {
		// All values are the same, create leaf
		return &IsolationTree{
			root: &IsolationNode{
				size:   len(data),
				isLeaf: true,
			},
			height: depth,
		}
	}

	// Randomly select split value
	splitValue := minVal + rand.Float64()*(maxVal-minVal)

	// Split data
	leftData, rightData := f.splitData(data, featureName, splitValue)

	// Recursively build subtrees
	leftTree := f.buildTree(leftData, depth+1)
	rightTree := f.buildTree(rightData, depth+1)

	// Create internal node
	root := &IsolationNode{
		feature: featureName,
		value:   splitValue,
		size:    len(data),
		isLeaf:  false,
	}

	if leftTree != nil && leftTree.root != nil {
		root.left = leftTree.root
	}
	if rightTree != nil && rightTree.root != nil {
		root.right = rightTree.root
	}

	return &IsolationTree{
		root:   root,
		height: max(leftTree.height, rightTree.height) + 1,
	}
}

// findMinMax finds the min and max values for a feature
func (f *IsolationForest) findMinMax(data []*FeatureVector, featureName string) (float64, float64) {
	minVal := math.MaxFloat64
	maxVal := -math.MaxFloat64

	for _, fv := range data {
		if value, exists := fv.Features[featureName]; exists {
			if value < minVal {
				minVal = value
			}
			if value > maxVal {
				maxVal = value
			}
		}
	}

	if minVal == math.MaxFloat64 {
		return 0, 0 // No valid values found
	}

	return minVal, maxVal
}

// splitData splits data based on feature and value
func (f *IsolationForest) splitData(data []*FeatureVector, featureName string, splitValue float64) ([]*FeatureVector, []*FeatureVector) {
	left := make([]*FeatureVector, 0)
	right := make([]*FeatureVector, 0)

	for _, fv := range data {
		if value, exists := fv.Features[featureName]; exists {
			if value <= splitValue {
				left = append(left, fv)
			} else {
				right = append(right, fv)
			}
		} else {
			// Feature not present, randomly assign
			if rand.Float64() < 0.5 {
				left = append(left, fv)
			} else {
				right = append(right, fv)
			}
		}
	}

	return left, right
}

// pathLength calculates the path length from root to leaf for a feature vector
func (f *IsolationForest) pathLength(node *IsolationNode, features *FeatureVector, currentLength float64) float64 {
	if node == nil || node.isLeaf {
		// Reached a leaf, return path length with adjustment for tree size
		if node != nil && node.size > 1 {
			return currentLength + f.averagePathLength(node.size)
		}
		return currentLength
	}

	// Traverse based on feature value
	featureValue, exists := features.Features[node.feature]
	if !exists {
		// Feature not present, randomly choose path
		if rand.Float64() < 0.5 {
			return f.pathLength(node.left, features, currentLength+1)
		}
		return f.pathLength(node.right, features, currentLength+1)
	}

	if featureValue <= node.value {
		return f.pathLength(node.left, features, currentLength+1)
	}
	return f.pathLength(node.right, features, currentLength+1)
}

// averagePathLength calculates the average path length for a tree with n nodes
func (f *IsolationForest) averagePathLength(n int) float64 {
	if n <= 1 {
		return 0
	}

	// Average path length of unsuccessful search in BST: 2H(n-1) - 2(n-1)/n
	// where H is the harmonic number
	harmonic := 0.0
	for i := 1; i <= n-1; i++ {
		harmonic += 1.0 / float64(i)
	}

	return 2*harmonic - 2*float64(n-1)/float64(n)
}

// anomalyScore converts path length to anomaly score
func (f *IsolationForest) anomalyScore(pathLength float64, sampleSize int) float64 {
	if sampleSize <= 1 {
		return 0.5
	}

	// Anomaly score formula from the original paper
	c := f.averagePathLength(sampleSize)
	score := math.Pow(2, -pathLength/c)

	// Clamp to [0, 1]
	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}

	return score
}
