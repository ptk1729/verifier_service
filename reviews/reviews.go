package reviews

type ReviewDetail struct {
	Reviewer string `json:"reviewer"`
	Approved bool   `json:"approved"`
}

type ReviewsResult struct {
	Status          ResultStatus   `json:"status"`
	RequiredReviews int            `json:"required_reviews"`
	ActualReviews   int            `json:"actual_reviews"`
	Details         []ReviewDetail `json:"details"`
}

type ResultStatus string

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)

// CheckReviews checks if the required number of reviews are present and approved
func CheckReviews(requiredReviews int) ReviewsResult {
	// TODO: Implement actual review checking logic
	// For now, using dummy data as in the original code
	reviews := []ReviewDetail{
		{Reviewer: "bob@example.com", Approved: true},
	}

	status := ResultStatusFailed
	if len(reviews) >= requiredReviews {
		status = ResultStatusPassed
	}

	return ReviewsResult{
		Status:          status,
		RequiredReviews: requiredReviews,
		ActualReviews:   len(reviews),
		Details:         reviews,
	}
}
