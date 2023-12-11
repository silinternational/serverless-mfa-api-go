package api

// swagger:model
type TotpCreateOutput struct {
	ID       string `json:"uuid"`
	Key      string `json:"totpKey"`
	AuthURL  string `json:"otpAuthUrl"`
	ImageURL string `json:"imageUrl"`
}

// swagger:model
type TotpValidateInput struct {
	Code string `json:"code" form:"code" binding:"required"`
}

// swagger:model
type TotpValidateOutput struct {
	Message string `json:"message"`
}
