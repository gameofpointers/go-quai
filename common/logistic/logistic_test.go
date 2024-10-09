package logistic

import (
	"fmt"
	"math"
	"testing"

	"golang.org/x/exp/rand"
)

func TestLogistic(t *testing.T) {
	r := NewLogisticRegression()

	x := []float64{10, 20, 30, 40}
	y := []float64{0.4, 0.6, 0.7, 0.3}

	r.Train(x, y)

	fmt.Println("Beta0/1 after training", r.Beta0(), r.Beta1())
}

func TestLogisticOnRandomData(t *testing.T) {
	// Initialize the logistic regression model
	r := NewLogisticRegression()

	// Number of samples
	nSamples := 100

	// Generate random x values between 0 and 100
	x := make([]float64, nSamples)
	y := make([]float64, nSamples)

	rand.Seed(1000) // Seed the random number generator

	for i := 0; i < nSamples; i++ {
		x[i] = rand.Float64() * 100 // x between 0 and 100

		// Define a logistic function to compute the probability
		prob := 1.0 / (1.0 + math.Exp(-0.1*(x[i]-50))) // Centered at x=50

		// Assign labels based on the probability
		if rand.Float64() < prob {
			y[i] = 1.0 // Class 1
		} else {
			y[i] = 0.0 // Class 0
		}
	}

	// Train the model
	r.Train(x, y)

	// Output the learned parameters
	fmt.Println("Beta0/1 after training", r.Beta0(), r.Beta1())
}
