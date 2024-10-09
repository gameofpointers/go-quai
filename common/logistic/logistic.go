package logistic

import (
	"math"
)

const c_LearningRate = 0.00001
const c_epochs = 10000000

// LogisticRegression represents a logistic regression model.
type LogisticRegression struct {
	beta1  float64 // Model weights
	beta0  float64 // Model bias
	Epochs int     // Number of training epochs
}

// NewLogisticRegression initializes a new LogisticRegression model.
func NewLogisticRegression() *LogisticRegression {
	return &LogisticRegression{
		beta1: 0.5,
		beta0: 0.5, // Initialize bias to 0.5
	}
}

// sigmoid computes the sigmoid function.
func sigmoid(z float64) float64 {
	return 1.0 / (1.0 + math.Exp(-z))
}

// Predict computes the probability that the input belongs to class 1.
func (lr *LogisticRegression) Predict(x float64) float64 {
	z := lr.beta0
	z += lr.beta1 * x
	return sigmoid(z)
}

// PredictLabel predicts the class label (0 or 1) for the input.
func (lr *LogisticRegression) PredictLabel(x float64) int {
	prob := lr.Predict(x)
	if prob >= 0.5 {
		return 1
	}
	return 0
}

// Train trains the logistic regression model using gradient descent.
func (lr *LogisticRegression) Train(x []float64, y []float64) {
	nSamples := len(y)

	for epoch := 0; epoch < c_epochs; epoch++ {
		// Initialize gradients
		dw := 0.0
		db := 0.0

		// Compute gradients
		for i := 0; i < nSamples; i++ {
			xi := x[i]
			yi := y[i]
			pred := lr.Predict(xi)
			error := pred - yi
			dw += error * xi
			db += error
		}

		// Update weight and bias
		lr.beta1 -= c_LearningRate * dw / float64(nSamples)
		lr.beta0 -= c_LearningRate * db / float64(nSamples)
	}
}

func (lr *LogisticRegression) Beta0() float64 {
	return lr.beta0
}

func (lr *LogisticRegression) Beta1() float64 {
	return lr.beta1
}
